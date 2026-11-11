"""
Protocol and Cryptographic Configuration for ECC-based IoT Secure Communication.
"""

# Curve & Cryptographic Primitives
ECC_CURVE_NAME = "secp256r1"  # NIST P-256 (standard for constrained & commercial IoT, TLS 1.3)
HASH_ALGO = "SHA256"
SYMMETRIC_CIPHER = "AES-GCM"
KEY_SIZE_BITS = 256
AES_KEY_SIZE_BYTES = 32  # AES-256
GCM_IV_SIZE_BYTES = 12   # Standard 96-bit IV for AES-GCM
GCM_TAG_SIZE_BYTES = 16  # 128-bit authentication tag

# Anti-Replay and Freshness Parameters
MAX_ALLOWED_CLOCK_SKEW_SECONDS = 30.0  # Max acceptable time divergence
REPLAY_WINDOW_SIZE = 64                # Sliding window size for packet sequence IDs

# Simulated Network Parameters
DEFAULT_GATEWAY_HOST = "localhost"
DEFAULT_GATEWAY_PORT = 8888

# Academic Benchmark Settings
BENCHMARK_ITERATIONS = 50
RSA_KEY_SIZES = [2048, 3072]
ECC_KEY_SIZE = 256  # Equivalent to RSA 3072 in security strength (128-bit security level)
