"""
Key Derivation Function (HKDF) based on RFC 5869.
Expands raw ECDH shared secrets into cryptographically strong, domain-separated session keys.
"""

from typing import Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import config

@dataclass
class SessionKeys:
    """Contains derived session keys for authenticated encryption and protocol integrity."""
    encryption_key: bytes  # 32 bytes for AES-256
    mac_key: bytes         # 32 bytes for HMAC or secondary verification
    base_iv: bytes         # 12 bytes base IV

def derive_session_keys(
    shared_secret: bytes,
    salt: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
    context_info: str = "ECC-IoT-Session-v1"
) -> SessionKeys:
    """
    Derives cryptographically strong session keys using HKDF-SHA256.
    
    Info parameter binds client nonce, server nonce, and protocol context to prevent
    pre-computation and replay attacks.
    """
    info = f"{context_info}|{client_nonce.hex()}|{server_nonce.hex()}".encode("utf-8")
    
    # 32 bytes (enc) + 32 bytes (mac) + 12 bytes (iv) = 76 bytes total
    total_key_material_len = config.AES_KEY_SIZE_BYTES + 32 + config.GCM_IV_SIZE_BYTES
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=total_key_material_len,
        salt=salt,
        info=info
    )
    
    key_material = hkdf.derive(shared_secret)
    
    enc_key = key_material[:config.AES_KEY_SIZE_BYTES]
    mac_key = key_material[config.AES_KEY_SIZE_BYTES:config.AES_KEY_SIZE_BYTES + 32]
    base_iv = key_material[config.AES_KEY_SIZE_BYTES + 32:]
    
    return SessionKeys(
        encryption_key=enc_key,
        mac_key=mac_key,
        base_iv=base_iv
    )
