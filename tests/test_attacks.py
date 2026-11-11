"""
Automated Security Test Suite.
Verifies that all simulated adversarial attacks (Eavesdropping, MITM, Tamper, Replay)
are successfully mitigated by our ECC-based protocol.
"""

import unittest
from crypto.ecdsa_auth import CertificateAuthority
from protocol.node import IoTNode
from protocol.gateway import IoTGateway
from simulation.attacks import AttackSimulator

class TestSecurityAttacks(unittest.TestCase):

    def setUp(self):
        self.ca = CertificateAuthority("Test-Security-CA")
        self.gateway = IoTGateway.register_new("Gateway-Secure-01", self.ca)
        self.node = IoTNode.register_new("Sensor-Industrial-01", self.ca)

        # Establish legitimate session
        client_hello = self.node.start_handshake()
        _, server_hello, _ = self.gateway.handle_client_hello(client_hello)
        self.node.process_server_hello(server_hello)

    def test_mitm_attack_mitigation(self):
        """Verify that MITM key substitution and rogue CA attacks are blocked."""
        # Need a fresh node for handshake test
        fresh_node = IoTNode.register_new("Sensor-Fresh", self.ca)
        res = AttackSimulator.simulate_mitm_attack(fresh_node, self.gateway)
        self.assertEqual(res["scenario_1_result"], "BLOCKED")
        self.assertEqual(res["scenario_2_result"], "BLOCKED")

    def test_tamper_attack_mitigation(self):
        """Verify that tampering with ciphertext or header is blocked by AEAD tag."""
        res = AttackSimulator.simulate_tamper_attack(self.node, self.gateway)
        self.assertTrue(res["ciphertext_tamper_blocked"])
        self.assertTrue(res["header_aad_tamper_blocked"])

    def test_replay_attack_mitigation(self):
        """Verify that replayed packets and delayed packets are rejected."""
        res = AttackSimulator.simulate_replay_attack(self.node, self.gateway)
        self.assertTrue(res["original_packet_accepted"])
        self.assertTrue(res["immediate_replay_blocked"])
        self.assertTrue(res["delayed_replay_blocked"])

    def test_eavesdropping_entropy(self):
        """Verify that ciphertext has high entropy and conceals plaintext."""
        res = AttackSimulator.simulate_eavesdropping(self.node, self.gateway)
        self.assertTrue(res["confidentiality_preserved"])
        self.assertGreater(res["shannon_entropy"], 6.0)
        self.assertGreater(res["entropy_efficiency_pct"], 90.0)

if __name__ == "__main__":
    unittest.main()
