"""
Unit tests for the protocol handshake, session derivation, and telemetry transmission.
"""

import unittest
from crypto.ecdsa_auth import CertificateAuthority
from protocol.node import IoTNode
from protocol.gateway import IoTGateway

class TestProtocolLayer(unittest.TestCase):

    def setUp(self):
        self.ca = CertificateAuthority("Test-IoT-RootCA")
        self.gateway = IoTGateway.register_new("Gateway-01", self.ca)
        self.node = IoTNode.register_new("Sensor-Temp-01", self.ca)

    def test_full_handshake_flow(self):
        """Test mutual ECDH handshake and key establishment."""
        client_hello = self.node.start_handshake()
        success, server_hello, msg = self.gateway.handle_client_hello(client_hello)
        self.assertTrue(success, f"Gateway rejected handshake: {msg}")

        success, msg = self.node.process_server_hello(server_hello)
        self.assertTrue(success, f"Node rejected server hello: {msg}")

        # Both ends must have matching session IDs
        self.assertEqual(self.node.session_id, self.gateway.node_to_session[self.node.node_id])
        session = self.gateway.sessions[self.node.session_id]

        # Both ends must have identical encryption and MAC keys
        self.assertEqual(self.node.session_keys.encryption_key, session.keys.encryption_key)
        self.assertEqual(self.node.session_keys.mac_key, session.keys.mac_key)
        self.assertEqual(self.node.session_keys.base_iv, session.keys.base_iv)

    def test_telemetry_encryption_and_gateway_decryption(self):
        """Test end-to-end encrypted telemetry transmission."""
        # 1. Handshake
        client_hello = self.node.start_handshake()
        _, server_hello, _ = self.gateway.handle_client_hello(client_hello)
        self.node.process_server_hello(server_hello)

        # 2. Telemetry Packet 1
        sample_payload = {"temperature_c": 28.75, "humidity_pct": 55.2}
        packet1 = self.node.create_telemetry_packet(custom_payload=sample_payload)

        success, received_payload, ack, msg = self.gateway.receive_telemetry(packet1)
        self.assertTrue(success, f"Gateway failed to process packet: {msg}")
        self.assertEqual(received_payload["temperature_c"], 28.75)
        self.assertEqual(received_payload["humidity_pct"], 55.2)
        self.assertEqual(ack.ack_sequence_num, 1)

        # 3. Telemetry Packet 2
        packet2 = self.node.create_telemetry_packet()
        success, received_payload2, ack2, msg = self.gateway.receive_telemetry(packet2)
        self.assertTrue(success)
        self.assertEqual(ack2.ack_sequence_num, 2)

if __name__ == "__main__":
    unittest.main()

