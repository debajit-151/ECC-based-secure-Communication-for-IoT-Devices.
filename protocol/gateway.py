"""
IoT Edge Gateway (Cloud / Fog Aggregator).
Handles secure handshakes, manages active sessions, performs anti-replay checks,
and decrypts authenticated telemetry from IoT nodes.
"""

import os
import time
import json
import hashlib
from typing import Dict, Any, Tuple, Optional
from crypto.ecdh import ECDHManager
from crypto.ecdsa_auth import ECDSASigner, CertificateAuthority
from crypto.kdf import derive_session_keys, SessionKeys
from crypto.aead_cipher import AEADCipher
from .messages import ClientHelloMessage, ServerHelloMessage, TelemetryPacket, AckPacket
import config

class GatewaySession:
    def __init__(self, session_id: str, node_id: str, keys: SessionKeys):
        self.session_id = session_id
        self.node_id = node_id
        self.keys = keys
        self.cipher = AEADCipher(keys.encryption_key)
        self.last_seq: int = 0
        self.seen_sequences: set = set()
        self.established_at: float = time.time()
        self.packet_count: int = 0

class IoTGateway:
    """Represents an IoT Gateway, Fog Broker, or Cloud Ingestion Server."""

    def __init__(self, server_id: str, ca_public_bytes: bytes, cert: Dict[str, Any], identity_signer: ECDSASigner):
        self.server_id = server_id
        self.ca_public_bytes = ca_public_bytes
        self.cert = cert
        self.identity_signer = identity_signer

        # Active node sessions: session_id -> GatewaySession
        self.sessions: Dict[str, GatewaySession] = {}
        # Node lookup table: node_id -> session_id
        self.node_to_session: Dict[str, str] = {}
        # Audit log of received messages and security alerts
        self.audit_log: list = []

    @classmethod
    def register_new(cls, server_id: str, ca: CertificateAuthority) -> "IoTGateway":
        """Factory: Generates long-term identity key and obtains certified credentials from CA."""
        identity_signer = ECDSASigner.generate()
        cert = ca.issue_certificate(server_id, identity_signer.get_public_bytes())
        return cls(
            server_id=server_id,
            ca_public_bytes=ca.get_ca_public_bytes(),
            cert=cert,
            identity_signer=identity_signer
        )

    def handle_client_hello(self, client_hello: ClientHelloMessage) -> Tuple[bool, Optional[ServerHelloMessage], str]:
        """
        Step 1 & 2: Receives ClientHello, authenticates node certificate & signature,
        computes ECDH shared secret, derives HKDF session keys, and produces ServerHello.
        """
        # 1. Verify Client Certificate with Root CA
        client_cert = client_hello.identity_cert
        client_cert_copy = dict(client_cert)
        client_sig_hex = client_cert_copy.pop("signature_hex", None)
        if not client_sig_hex:
            return False, None, "Client certificate missing CA signature"

        ca_valid = ECDSASigner.verify(
            bytes.fromhex(client_sig_hex),
            json.dumps(client_cert_copy, sort_keys=True).encode("utf-8"),
            self.ca_public_bytes
        )
        if not ca_valid:
            return False, None, "Client certificate rejected: Untrusted CA or revoked"

        # 2. Check Node ID consistency
        if client_cert.get("device_id") != client_hello.node_id:
            return False, None, "Node ID mismatch between certificate and hello message"

        # 3. Verify Client ECDSA Signature over handshake parameters
        client_pubkey_bytes = bytes.fromhex(client_cert["pubkey_hex"])
        signed_payload = client_hello.get_signed_payload_bytes()
        sig_valid = ECDSASigner.verify(
            bytes.fromhex(client_hello.signature_hex),
            signed_payload,
            client_pubkey_bytes
        )
        if not sig_valid:
            return False, None, "Client handshake signature invalid (Impersonation/MITM attempt)"

        # 4. Generate Server Ephemeral ECDH Keypair & Nonce
        server_ecdh = ECDHManager.generate()
        server_nonce = os.urandom(16)
        server_timestamp = time.time()
        server_eph_pub_hex = server_ecdh.get_public_bytes().hex()

        # 5. Sign ServerHello parameters including client_nonce
        server_signed_payload = f"{self.server_id}:{server_nonce.hex()}:{server_timestamp}:{server_eph_pub_hex}:{client_hello.client_nonce_hex}".encode("utf-8")
        server_sig = self.identity_signer.sign(server_signed_payload)

        server_hello = ServerHelloMessage(
            server_id=self.server_id,
            server_nonce_hex=server_nonce.hex(),
            timestamp=server_timestamp,
            ephemeral_pubkey_hex=server_eph_pub_hex,
            identity_cert=self.cert,
            signature_hex=server_sig.hex()
        )

        # 6. Compute ECDH Shared Secret: Z = d_server * Q_client
        client_eph_pubkey_bytes = bytes.fromhex(client_hello.ephemeral_pubkey_hex)
        shared_secret = server_ecdh.compute_shared_secret(client_eph_pubkey_bytes)

        # 7. Derive HKDF Session Keys
        client_nonce = bytes.fromhex(client_hello.client_nonce_hex)
        salt = bytes(a ^ b for a, b in zip(client_nonce, server_nonce))
        session_keys = derive_session_keys(
            shared_secret=shared_secret,
            salt=salt,
            client_nonce=client_nonce,
            server_nonce=server_nonce
        )

        # 8. Compute Session ID & Register Session
        session_material = (
            client_hello.node_id.encode("utf-8") +
            client_nonce +
            server_nonce +
            shared_secret
        )
        session_id = hashlib.sha256(session_material).hexdigest()[:16]

        session = GatewaySession(session_id=session_id, node_id=client_hello.node_id, keys=session_keys)
        self.sessions[session_id] = session
        self.node_to_session[client_hello.node_id] = session_id

        self.audit_log.append({
            "timestamp": time.time(),
            "event": "SESSION_ESTABLISHED",
            "node_id": client_hello.node_id,
            "session_id": session_id,
            "status": "SUCCESS"
        })

        return True, server_hello, f"Session established: {session_id}"

    def receive_telemetry(self, packet: TelemetryPacket) -> Tuple[bool, Optional[Dict[str, Any]], Optional[AckPacket], str]:
        """
        Processes an incoming TelemetryPacket:
        - Validates session existence.
        - Checks timestamp freshness against max clock skew (anti-delayed attack).
        - Checks sequence monotonicity (anti-replay attack).
        - Verifies AES-GCM authentication tag and decrypts sensor readings.
        """
        header = packet.header
        session_id = header.session_id

        if session_id not in self.sessions:
            return False, None, None, f"Unknown or expired session ID: {session_id}"

        session = self.sessions[session_id]

        # 1. Freshness Check (Anti-Delay / Clock Skew Protection)
        now = time.time()
        time_delta = abs(now - header.timestamp)
        if time_delta > config.MAX_ALLOWED_CLOCK_SKEW_SECONDS:
            return False, None, None, f"Packet rejected: Timestamp expired or skewed ({time_delta:.1f}s > {config.MAX_ALLOWED_CLOCK_SKEW_SECONDS}s)"

        # 2. Anti-Replay Check (Sequence Number Verification)
        if header.sequence_num <= session.last_seq or header.sequence_num in session.seen_sequences:
            return False, None, None, f"REPLAY ATTACK DETECTED: Sequence #{header.sequence_num} already processed (last={session.last_seq})"

        # 3. Authenticated Decryption with Associated Data (AEAD AES-256-GCM)
        aad_bytes = header.to_aad_bytes()
        ciphertext_and_tag = bytes.fromhex(packet.ciphertext_hex)
        iv_bytes = bytes.fromhex(header.iv_hex)

        try:
            decrypted_bytes = session.cipher.decrypt(ciphertext_and_tag, aad_bytes, iv_bytes)
            payload = json.loads(decrypted_bytes.decode("utf-8"))
        except Exception as e:
            return False, None, None, f"CRYPTOGRAPHIC INTEGRITY FAILURE: AES-GCM tag verification failed (Tampering detected!) [{str(e)}]"

        # Update Session Sequence Tracking
        session.last_seq = header.sequence_num
        session.seen_sequences.add(header.sequence_num)
        session.packet_count += 1

        ack = AckPacket(
            node_id=header.node_id,
            session_id=session_id,
            ack_sequence_num=header.sequence_num,
            status="VERIFIED_AND_INGESTED",
            timestamp=time.time()
        )

        self.audit_log.append({
            "timestamp": time.time(),
            "event": "TELEMETRY_INGESTED",
            "node_id": header.node_id,
            "seq": header.sequence_num,
            "session_id": session_id,
            "status": "AUTHENTICATED"
        })

        return True, payload, ack, "Packet authenticated and decrypted successfully"
