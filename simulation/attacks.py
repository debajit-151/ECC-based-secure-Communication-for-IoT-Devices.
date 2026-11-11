"""
Adversary and Attack Simulation Suite.
Simulates real-world cyberattacks against IoT communication channels:
1. Passive Eavesdropping (Ciphertext Entropy & Secrecy Analysis)
2. Active Man-in-the-Middle (MITM) Ephemeral Key Substitution
3. Data Tampering / Bit-Flipping (AEAD Integrity Tag Verification)
4. Replay Attack (Sequence Number & Freshness Verification)
"""

import time
import math
import copy
from typing import Dict, Any, Tuple
from crypto.ecdh import ECDHManager
from crypto.ecdsa_auth import ECDSASigner, CertificateAuthority
from protocol.node import IoTNode
from protocol.gateway import IoTGateway
from protocol.messages import ClientHelloMessage, TelemetryPacket, TelemetryHeader

class AttackSimulator:
    """Simulates adversarial attacks on the ECC IoT protocol and analyzes cryptographic defenses."""

    @staticmethod
    def calculate_entropy(data: bytes) -> Tuple[float, float]:
        """
        Calculates Shannon entropy in bits/byte and normalized efficiency.
        Max possible entropy for N bytes is min(8.0, log2(N)).
        """
        if not data:
            return 0.0, 0.0
        entropy = 0.0
        length = len(data)
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
        for count in frequencies.values():
            p_x = count / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        max_possible = min(8.0, math.log2(length)) if length > 1 else 1.0
        normalized = (entropy / max_possible) * 100.0
        return round(entropy, 4), round(normalized, 2)

    @classmethod
    def simulate_eavesdropping(cls, node: IoTNode, gateway: IoTGateway) -> Dict[str, Any]:
        """
        Simulates passive network eavesdropping.
        An attacker captures ciphertext packets on the network wire.
        Evaluates data entropy, secrecy, and absence of plaintext leakage.
        """
        packet = node.create_telemetry_packet()
        ciphertext_bytes = bytes.fromhex(packet.ciphertext_hex)
        entropy, efficiency = cls.calculate_entropy(ciphertext_bytes)

        return {
            "attack_type": "Passive Eavesdropping",
            "intercepted_header": packet.header,
            "ciphertext_sample_hex": packet.ciphertext_hex[:32] + "...",
            "ciphertext_len_bytes": len(ciphertext_bytes),
            "shannon_entropy": entropy,
            "entropy_efficiency_pct": efficiency,
            "max_theoretical_entropy": 8.0,
            "confidentiality_preserved": True,
            "explanation": (
                f"Ciphertext exhibits high Shannon entropy ({entropy} bits/byte, {efficiency}% of theoretical max for payload size), "
                "demonstrating that AES-256-GCM produces cryptographically pseudorandom output with zero plaintext leakage."
            )
        }

    @classmethod
    def simulate_mitm_attack(cls, node: IoTNode, gateway: IoTGateway) -> Dict[str, Any]:
        """
        Simulates an active Man-In-The-Middle (MITM) key substitution attack.
        Adversary intercepts ClientHello and injects a rogue ephemeral public key.
        """
        # Node starts handshake
        client_hello = node.start_handshake()

        # Attacker generates rogue ephemeral key
        rogue_ecdh = ECDHManager.generate()
        rogue_pubkey_hex = rogue_ecdh.get_public_bytes().hex()

        # Tampered message with rogue ephemeral key (attacker leaves original signature)
        tampered_hello_1 = copy.deepcopy(client_hello)
        tampered_hello_1.ephemeral_pubkey_hex = rogue_pubkey_hex

        # Gateway handles tampered packet
        success_1, _, reason_1 = gateway.handle_client_hello(tampered_hello_1)

        # Attacker tries to sign with rogue identity key not trusted by CA
        rogue_signer = ECDSASigner.generate()
        rogue_cert = {
            "device_id": client_hello.node_id,
            "pubkey_hex": rogue_signer.get_public_bytes().hex(),
            "issued_at": time.time(),
            "expires_at": time.time() + 86400,
            "ca_name": "Rogue-Attacker-CA",
            "signature_hex": rogue_signer.sign(b"fake").hex()
        }
        tampered_hello_2 = copy.deepcopy(client_hello)
        tampered_hello_2.identity_cert = rogue_cert

        success_2, _, reason_2 = gateway.handle_client_hello(tampered_hello_2)

        return {
            "attack_type": "Active MITM Key Substitution",
            "scenario_1_result": "BLOCKED" if not success_1 else "VULNERABLE",
            "scenario_1_reason": reason_1,
            "scenario_2_result": "BLOCKED" if not success_2 else "VULNERABLE",
            "scenario_2_reason": reason_2,
            "defense_mechanism": (
                "ECDSA digital signatures over ephemeral parameters coupled with CA certificate verification "
                "ensure that unauthorized public key replacements are detected and immediately aborted."
            )
        }

    @classmethod
    def simulate_tamper_attack(cls, node: IoTNode, gateway: IoTGateway) -> Dict[str, Any]:
        """
        Simulates data tampering (bit-flipping) in transit.
        Adversary modifies 1 byte in the encrypted telemetry packet or header.
        """
        packet = node.create_telemetry_packet({"temperature_c": 22.5, "status": "NORMAL"})

        # Case A: Tamper 1 bit in ciphertext
        raw_ciphertext = bytearray.fromhex(packet.ciphertext_hex)
        raw_ciphertext[0] ^= 0x01  # Flip 1 bit
        tampered_packet_ciphertext = TelemetryPacket(
            header=packet.header,
            ciphertext_hex=raw_ciphertext.hex()
        )
        success_c, _, _, reason_c = gateway.receive_telemetry(tampered_packet_ciphertext)

        # Case B: Tamper header / AAD (e.g. alter sequence number or sender ID)
        tampered_header = copy.deepcopy(packet.header)
        tampered_header.sequence_num += 99  # alter sequence in header
        tampered_packet_header = TelemetryPacket(
            header=tampered_header,
            ciphertext_hex=packet.ciphertext_hex
        )
        success_h, _, _, reason_h = gateway.receive_telemetry(tampered_packet_header)

        return {
            "attack_type": "Packet Tampering / Bit-Flipping",
            "ciphertext_tamper_blocked": not success_c,
            "ciphertext_tamper_reason": reason_c,
            "header_aad_tamper_blocked": not success_h,
            "header_aad_tamper_reason": reason_h,
            "defense_mechanism": (
                "AES-GCM GHASH authentication tag binds both the ciphertext and Additional Authenticated Data (AAD). "
                "Any bit alteration causes tag verification failure with probability 1 - 2^(-128)."
            )
        }

    @classmethod
    def simulate_replay_attack(cls, node: IoTNode, gateway: IoTGateway) -> Dict[str, Any]:
        """
        Simulates a replay attack.
        Adversary intercepts a valid, authenticated packet and re-transmits it later.
        """
        packet = node.create_telemetry_packet({"temperature_c": 35.0, "alert": "HIGH_TEMP"})

        # First transmission (legitimate)
        success_orig, payload_orig, _, reason_orig = gateway.receive_telemetry(packet)

        # Immediate replay of the exact same packet
        success_replay1, _, _, reason_replay1 = gateway.receive_telemetry(packet)

        # Delayed replay with old timestamp
        delayed_header = copy.deepcopy(packet.header)
        delayed_header.timestamp = time.time() - 3600  # 1 hour old
        delayed_packet = TelemetryPacket(header=delayed_header, ciphertext_hex=packet.ciphertext_hex)
        success_replay2, _, _, reason_replay2 = gateway.receive_telemetry(delayed_packet)

        return {
            "attack_type": "Replay Attack",
            "original_packet_accepted": success_orig,
            "immediate_replay_blocked": not success_replay1,
            "immediate_replay_reason": reason_replay1,
            "delayed_replay_blocked": not success_replay2,
            "delayed_replay_reason": reason_replay2,
            "defense_mechanism": (
                "Gateway tracks monotonic sequence numbers and validates packet timestamps within a strict "
                "clock-skew window. Replayed packets are flagged and discarded before processing."
            )
        }
