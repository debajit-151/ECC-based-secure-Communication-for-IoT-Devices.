"""
Core Cryptographic Modules for ECC-based IoT Secure Communication.
Provides ECDH, ECDSA, HKDF, and AEAD (AES-GCM) primitives.
"""

from .ecdh import ECDHManager
from .ecdsa_auth import ECDSASigner, CertificateAuthority
from .kdf import derive_session_keys
from .aead_cipher import AEADCipher

__all__ = [
    "ECDHManager",
    "ECDSASigner",
    "CertificateAuthority",
    "derive_session_keys",
    "AEADCipher",
]
