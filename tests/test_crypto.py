"""
Unit tests for core cryptographic primitives (Curves, ECDH, ECDSA, HKDF, AES-GCM).
"""

import os
import unittest
from crypto.curves import NIST_P256, is_point_on_curve
from crypto.ecdh import ECDHManager
from crypto.ecdsa_auth import ECDSASigner, CertificateAuthority
from crypto.kdf import derive_session_keys
from crypto.aead_cipher import AEADCipher
from cryptography.exceptions import InvalidTag

class TestCryptoPrimitives(unittest.TestCase):

    def test_curve_generator_point(self):
        """Test that generator point G lies on secp256r1 curve."""
        self.assertTrue(is_point_on_curve(NIST_P256.Gx, NIST_P256.Gy))

    def test_ecdh_key_exchange(self):
        """Test that IoT Node and Gateway compute identical shared secret."""
        node_ecdh = ECDHManager.generate()
        gateway_ecdh = ECDHManager.generate()

        secret_node = node_ecdh.compute_shared_secret(gateway_ecdh.get_public_bytes())
        secret_gateway = gateway_ecdh.compute_shared_secret(node_ecdh.get_public_bytes())

        self.assertEqual(secret_node, secret_gateway)
        self.assertEqual(len(secret_node), 32)  # 256-bit scalar

    def test_ecdsa_signing_and_verification(self):
        """Test digital signatures for non-repudiation."""
        signer = ECDSASigner.generate()
        message = b"IoT-Sensor-Data-Readings"
        signature = signer.sign(message)

        # Verification succeeds with correct key
        self.assertTrue(ECDSASigner.verify(signature, message, signer.get_public_bytes()))

        # Verification fails if message is tampered
        tampered_msg = b"IoT-Sensor-Data-Tampered"
        self.assertFalse(ECDSASigner.verify(signature, tampered_msg, signer.get_public_bytes()))

        # Verification fails with different key
        another_signer = ECDSASigner.generate()
        self.assertFalse(ECDSASigner.verify(signature, message, another_signer.get_public_bytes()))

    def test_certificate_authority(self):
        """Test CA certificate issuance and verification."""
        ca = CertificateAuthority("Test-IoT-RootCA")
        node_signer = ECDSASigner.generate()

        cert = ca.issue_certificate("sensor-temp-01", node_signer.get_public_bytes())
        valid, reason = ca.verify_certificate(cert)
        self.assertTrue(valid, f"CA cert verification failed: {reason}")

        # Tampered cert fails
        tampered_cert = dict(cert)
        tampered_cert["device_id"] = "hacker-device-99"
        valid, reason = ca.verify_certificate(tampered_cert)
        self.assertFalse(valid)

    def test_hkdf_key_derivation(self):
        """Test session key derivation with nonces."""
        shared_secret = os.urandom(32)
        salt = os.urandom(16)
        nonce_client = os.urandom(16)
        nonce_server = os.urandom(16)

        keys1 = derive_session_keys(shared_secret, salt, nonce_client, nonce_server)
        keys2 = derive_session_keys(shared_secret, salt, nonce_client, nonce_server)

        # Deterministic with same inputs
        self.assertEqual(keys1.encryption_key, keys2.encryption_key)
        self.assertEqual(keys1.mac_key, keys2.mac_key)
        self.assertEqual(keys1.base_iv, keys2.base_iv)
        self.assertEqual(len(keys1.encryption_key), 32)

        # Different nonces produce different session keys (forward secrecy / replay defense)
        different_nonce = os.urandom(16)
        keys3 = derive_session_keys(shared_secret, salt, different_nonce, nonce_server)
        self.assertNotEqual(keys1.encryption_key, keys3.encryption_key)

    def test_aead_encryption_and_tampering(self):
        """Test AES-256-GCM encryption, decryption, and integrity tag protection."""
        key = os.urandom(32)
        cipher = AEADCipher(key)
        plaintext = b'{"temp": 24.5, "pressure": 1013.25}'
        aad = b'{"node_id": "sensor-01", "seq": 1}'

        iv, ciphertext_and_tag = cipher.encrypt(plaintext, aad)
        decrypted = cipher.decrypt(ciphertext_and_tag, aad, iv)
        self.assertEqual(decrypted, plaintext)

        # Tampering with ciphertext triggers InvalidTag
        tampered_ciphertext = bytearray(ciphertext_and_tag)
        tampered_ciphertext[0] ^= 0xFF
        with self.assertRaises(InvalidTag):
            cipher.decrypt(bytes(tampered_ciphertext), aad, iv)

        # Tampering with AAD (e.g. modifying sequence number or sender ID) triggers InvalidTag
        tampered_aad = b'{"node_id": "sensor-01", "seq": 2}'
        with self.assertRaises(InvalidTag):
            cipher.decrypt(ciphertext_and_tag, tampered_aad, iv)

if __name__ == "__main__":
    unittest.main()
