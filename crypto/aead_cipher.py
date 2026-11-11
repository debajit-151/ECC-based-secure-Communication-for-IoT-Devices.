"""
Authenticated Encryption with Associated Data (AEAD) using AES-256-GCM.
Provides Confidentiality, Integrity, and Authenticity for IoT telemetry packets.
"""

import os
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import config

class AEADCipher:
    """AES-256-GCM Authenticated Encryption Engine."""

    def __init__(self, key: bytes):
        if len(key) != config.AES_KEY_SIZE_BYTES:
            raise ValueError(f"AES key must be exactly {config.AES_KEY_SIZE_BYTES} bytes.")
        self.aesgcm = AESGCM(key)

    @staticmethod
    def construct_unique_iv(base_iv: bytes, sequence_num: int) -> bytes:
        """
        Derives a strictly unique 12-byte IV for AES-GCM by XORing the base IV
        with the monotonic 64-bit sequence counter.
        This guarantees IV uniqueness and prevents catastrophic GCM IV reuse.
        """
        counter_bytes = sequence_num.to_bytes(8, byteorder="big")
        # Pad counter to 12 bytes
        padded_counter = b"\x00" * (config.GCM_IV_SIZE_BYTES - 8) + counter_bytes
        unique_iv = bytes(b ^ c for b, c in zip(base_iv, padded_counter))
        return unique_iv

    def encrypt(self, plaintext: bytes, associated_data: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        """
        Encrypts plaintext with AES-GCM.
        Returns (iv, ciphertext_with_tag).
        Note: AESGCM in cryptography appends the 16-byte tag to ciphertext.
        """
        if iv is None:
            iv = os.urandom(config.GCM_IV_SIZE_BYTES)
        
        ciphertext_and_tag = self.aesgcm.encrypt(iv, plaintext, associated_data)
        return iv, ciphertext_and_tag

    def decrypt(self, ciphertext_and_tag: bytes, associated_data: bytes, iv: bytes) -> bytes:
        """
        Decrypts ciphertext and validates GHASH authentication tag.
        Raises InvalidTag if ciphertext or associated data has been tampered with.
        """
        return self.aesgcm.decrypt(iv, ciphertext_and_tag, associated_data)

