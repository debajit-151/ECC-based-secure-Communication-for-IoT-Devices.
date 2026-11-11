"""
Simulated IoT Node (Sensor Device).
Performs mutual ECDH handshake, derives session keys via HKDF, and sends AES-GCM encrypted telemetry.
"""

import os
import time
import json
import random
import hashlib
from typing import Dict, Any, Optional, Tuple
from crypto.ecdh import ECDHManager
from crypto.ecdsa_auth import ECDSASigner, CertificateAuthority
from crypto.kdf import derive_session_keys, SessionKeys
from crypto.aead_cipher import AEADCipher
from .messages import ClientHelloMessage, ServerHelloMessage, TelemetryHeader, TelemetryPacket

class IoTNode:
    """Represents a resource-constrained IoT Edge Device (e.g., smart sensor / microcontroller)."""

    def __init__(self, node_id: str, ca_public_bytes: bytes, cert: Dict[str, Any], identity_signer: ECDSASigner):
        self.node_id = node_id
        self.ca_public_bytes = ca_public_bytes
        self.cert = cert
        self.identity_signer = identity_signer

        # Handshake Ephemeral State
        self.ephemeral_ecdh: Optional[ECDHManager] = None
        self.client_nonce: Optional[bytes] = None

        # Established Session State
        self.session_id: Optional[str] = None
        self.session_keys: Optional[SessionKeys] = None
        self.cipher: Optional[AEADCipher] = None
        self.sequence_counter: int = 0
        self.is_connected: bool = False

        # Telemetry sensor baseline
        self.base_temperature = round(random.uniform(20.0, 30.0), 2)
        self.base_humidity = round(random.uniform(40.0, 60.0), 2)
        self.battery_level = 100.0

    @classmethod
    def register_new(cls, node_id: str, ca: CertificateAuthority) -> "IoTNode":
        """Factory: Generates long-term identity key and obtains certified credentials from CA."""
        identity_signer = ECDSASigner.generate()
        cert = ca.issue_certificate(node_id, identity_signer.get_public_bytes())
        return cls(
            node_id=node_id,
            ca_public_bytes=ca.get_ca_public_bytes(),
            cert=cert,
            identity_signer=identity_signer
        )

    def start_handshake(self) -> ClientHelloMessage:
        """Step 1: Generate ephemeral ECDH keypair and produce signed ClientHello."""
        self.ephemeral_ecdh = ECDHManager.generate()
        self.client_nonce = os.urandom(16)
        timestamp = time.time()
        
        ephemeral_pub_hex = self.ephemeral_ecdh.get_public_bytes().hex()
        
        # Sign (node_id : client_nonce : timestamp : ephemeral_pubkey)
        data_to_sign = f"{self.node_id}:{self.client_nonce.hex()}:{timestamp}:{ephemeral_pub_hex}".encode("utf-8")
        sig = self.identity_signer.sign(data_to_sign)

        return ClientHelloMessage(
            node_id=self.node_id,
            client_nonce_hex=self.client_nonce.hex(),
            timestamp=timestamp,
            ephemeral_pubkey_hex=ephemeral_pub_hex,
            identity_cert=self.cert,
            signature_hex=sig.hex()
        )

    def process_server_hello(self, server_hello: ServerHelloMessage) -> Tuple[bool, str]:
        """
        Step 2: Authenticate Gateway ServerHello, verify signatures & certificates,
        compute ECDH shared secret, and derive HKDF session keys.
        """
        if self.ephemeral_ecdh is None or self.client_nonce is None:
            return False, "Handshake not initiated"

        # 1. Verify Gateway's Certificate with Root CA
        gw_cert = server_hello.identity_cert
        gw_cert_copy = dict(gw_cert)
        gw_sig_hex = gw_cert_copy.pop("signature_hex", None)
        if not gw_sig_hex:
            return False, "Gateway certificate is missing signature"
        
        ca_valid = ECDSASigner.verify(
            bytes.fromhex(gw_sig_hex),
            json.dumps(gw_cert_copy, sort_keys=True).encode("utf-8"),
            self.ca_public_bytes
        )
        if not ca_valid:
            return False, "Gateway certificate verification failed (Untrusted CA)"

        # 2. Verify Gateway's ECDSA Signature over ephemeral key and nonces
        gw_pubkey_bytes = bytes.fromhex(gw_cert["pubkey_hex"])
        signed_payload = server_hello.get_signed_payload_bytes(self.client_nonce.hex())
        sig_valid = ECDSASigner.verify(
            bytes.fromhex(server_hello.signature_hex),
            signed_payload,
            gw_pubkey_bytes
        )
        if not sig_valid:
            return False, "Gateway signature verification failed (MITM detected)"

        # 3. Compute ECDH Shared Secret: Z = d_client * Q_server
        peer_eph_pubkey_bytes = bytes.fromhex(server_hello.ephemeral_pubkey_hex)
        shared_secret = self.ephemeral_ecdh.compute_shared_secret(peer_eph_pubkey_bytes)

        # 4. Derive Session Keys via HKDF-SHA256
        server_nonce = bytes.fromhex(server_hello.server_nonce_hex)
        salt = bytes(a ^ b for a, b in zip(self.client_nonce, server_nonce))
        self.session_keys = derive_session_keys(
            shared_secret=shared_secret,
            salt=salt,
            client_nonce=self.client_nonce,
            server_nonce=server_nonce
        )

        # 5. Compute deterministic Session ID
        session_material = (
            self.node_id.encode("utf-8") +
            self.client_nonce +
            server_nonce +
            shared_secret
        )
        self.session_id = hashlib.sha256(session_material).hexdigest()[:16]

        self.cipher = AEADCipher(self.session_keys.encryption_key)
        self.sequence_counter = 0
        self.is_connected = True

        return True, f"Session established successfully [SessionID: {self.session_id}]"

    def read_sensors(self) -> Dict[str, Any]:
        """Simulates IoT environmental sensor readings (with slight random noise)."""
        temp_jitter = round(random.uniform(-0.4, 0.4), 2)
        hum_jitter = round(random.uniform(-1.0, 1.0), 2)
        self.battery_level = max(0.0, round(self.battery_level - 0.05, 2))

        return {
            "device_id": self.node_id,
            "temperature_c": round(self.base_temperature + temp_jitter, 2),
            "humidity_pct": round(self.base_humidity + hum_jitter, 2),
            "pressure_hpa": round(1013.25 + random.uniform(-2.0, 2.0), 2),
            "battery_pct": self.battery_level,
            "status": "HEALTHY" if self.battery_level > 20 else "LOW_BATTERY"
        }

    def create_telemetry_packet(self, custom_payload: Dict[str, Any] = None) -> TelemetryPacket:
        """Constructs and encrypts a secure telemetry packet with AES-256-GCM."""
        if not self.is_connected or self.cipher is None or self.session_keys is None:
            raise RuntimeError("Cannot send telemetry: Session is not established.")

        self.sequence_counter += 1
        now = time.time()

        # Construct deterministic unique IV: base_iv XOR sequence_counter
        unique_iv = AEADCipher.construct_unique_iv(self.session_keys.base_iv, self.sequence_counter)

        header = TelemetryHeader(
            node_id=self.node_id,
            session_id=self.session_id,
            sequence_num=self.sequence_counter,
            timestamp=now,
            iv_hex=unique_iv.hex()
        )

        payload_dict = custom_payload if custom_payload is not None else self.read_sensors()
        plaintext_bytes = json.dumps(payload_dict).encode("utf-8")
        aad_bytes = header.to_aad_bytes()

        _, ciphertext_and_tag = self.cipher.encrypt(
            plaintext=plaintext_bytes,
            associated_data=aad_bytes,
            iv=unique_iv
        )

        return TelemetryPacket(
            header=header,
            ciphertext_hex=ciphertext_and_tag.hex()
        )
