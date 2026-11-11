"""
Benchmarking Engine: Empirical Performance Comparison of ECC (secp256r1) vs RSA (2048-bit & 3072-bit).
Measures:
- Key Generation Latency
- Signing & Verification Time
- Key Exchange / Encryption Time
- Key and Signature Sizes (Memory & Bandwidth Overhead)
- Simulated Energy Consumption on ARM Cortex-M4 IoT Processor
"""

import os
import time
from typing import Dict, Any, List
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class CryptoBenchmarkRunner:
    """Executes empirical benchmarks comparing ECC (NIST P-256) and RSA (2048 & 3072)."""

    def __init__(self, iterations: int = 30):
        self.iterations = iterations

    def run_benchmarks(self) -> Dict[str, Any]:
        """Runs the complete comparative benchmark suite across ECC and RSA."""
        results = {
            "iterations": self.iterations,
            "algorithms": {
                "ECC-P256": self._benchmark_ecc(),
                "RSA-2048": self._benchmark_rsa(key_size=2048),
                "RSA-3072": self._benchmark_rsa(key_size=3072),
            }
        }
        return results

    def _benchmark_ecc(self) -> Dict[str, Any]:
        """Benchmarks ECC secp256r1 (128-bit security level)."""
        curve = ec.SECP256R1()
        test_payload = b"IoT-Sensor-Telemetry-Payload-Sample-2026"

        # 1. Key Generation
        keygen_times = []
        priv_keys = []
        for _ in range(self.iterations):
            t0 = time.perf_counter()
            k = ec.generate_private_key(curve)
            keygen_times.append((time.perf_counter() - t0) * 1000.0)
            if len(priv_keys) < 2:
                priv_keys.append(k)

        priv_key1, priv_key2 = priv_keys[0], priv_keys[1]
        pub_key1 = priv_key1.public_key()
        pub_key2 = priv_key2.public_key()

        # 2. Signing (ECDSA-SHA256)
        signing_times = []
        signatures = []
        for _ in range(self.iterations):
            t0 = time.perf_counter()
            sig = priv_key1.sign(test_payload, ec.ECDSA(hashes.SHA256()))
            signing_times.append((time.perf_counter() - t0) * 1000.0)
            signatures.append(sig)

        # 3. Verification
        verify_times = []
        sample_sig = signatures[0]
        for _ in range(self.iterations):
            t0 = time.perf_counter()
            pub_key1.verify(sample_sig, test_payload, ec.ECDSA(hashes.SHA256()))
            verify_times.append((time.perf_counter() - t0) * 1000.0)

        # 4. Key Agreement (ECDH)
        ecdh_times = []
        for _ in range(self.iterations):
            t0 = time.perf_counter()
            _ = priv_key1.exchange(ec.ECDH(), pub_key2)
            ecdh_times.append((time.perf_counter() - t0) * 1000.0)

        # 5. Sizes
        priv_raw_bytes = 32  # 256-bit scalar
        pub_der_bytes = len(pub_key1.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        sig_bytes = len(sample_sig)

        # ARM Cortex-M4 @ 64MHz (Power ≈ 33 mW) simulated energy: E (uJ) = P (mW) * time (ms)
        power_mw = 33.0
        avg_sign_ms = sum(signing_times) / len(signing_times)
        avg_ecdh_ms = sum(ecdh_times) / len(ecdh_times)
        simulated_sign_energy_uj = round(avg_sign_ms * power_mw, 3)
        simulated_ecdh_energy_uj = round(avg_ecdh_ms * power_mw, 3)

        return {
            "security_level_bits": 128,
            "keygen_time_ms": round(sum(keygen_times) / len(keygen_times), 3),
            "sign_time_ms": round(avg_sign_ms, 3),
            "verify_time_ms": round(sum(verify_times) / len(verify_times), 3),
            "key_exchange_time_ms": round(avg_ecdh_ms, 3),
            "private_key_size_bytes": priv_raw_bytes,
            "public_key_size_bytes": pub_der_bytes,
            "signature_size_bytes": sig_bytes,
            "simulated_energy_sign_uj": simulated_sign_energy_uj,
            "simulated_energy_handshake_uj": simulated_ecdh_energy_uj
        }

    def _benchmark_rsa(self, key_size: int) -> Dict[str, Any]:
        """Benchmarks RSA-2048 or RSA-3072."""
        test_payload = b"IoT-Sensor-Telemetry-Payload-Sample-2026"
        sec_level = 112 if key_size == 2048 else 128

        # 1. Key Generation (run fewer iterations if large to avoid high delay)
        keygen_iters = min(10, self.iterations)
        keygen_times = []
        priv_keys = []
        for _ in range(keygen_iters):
            t0 = time.perf_counter()
            k = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            keygen_times.append((time.perf_counter() - t0) * 1000.0)
            if len(priv_keys) < 2:
                priv_keys.append(k)

        priv_key1 = priv_keys[0]
        pub_key1 = priv_key1.public_key()

        # 2. Signing (RSA-PSS with SHA256)
        signing_times = []
        signatures = []
        for _ in range(self.iterations):
            t0 = time.perf_counter()
            sig = priv_key1.sign(
                test_payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            signing_times.append((time.perf_counter() - t0) * 1000.0)
            signatures.append(sig)

        # 3. Verification
        verify_times = []
        sample_sig = signatures[0]
        for _ in range(self.iterations):
            t0 = time.perf_counter()
            pub_key1.verify(
                sample_sig,
                test_payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            verify_times.append((time.perf_counter() - t0) * 1000.0)

        # 4. Key Encapsulation / Encryption (RSA-OAEP)
        enc_times = []
        sym_key = os.urandom(32)
        for _ in range(self.iterations):
            t0 = time.perf_counter()
            _ = pub_key1.encrypt(
                sym_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            enc_times.append((time.perf_counter() - t0) * 1000.0)

        # 5. Sizes
        priv_raw_bytes = key_size // 8
        pub_der_bytes = len(pub_key1.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        sig_bytes = len(sample_sig)

        power_mw = 33.0
        avg_sign_ms = sum(signing_times) / len(signing_times)
        avg_enc_ms = sum(enc_times) / len(enc_times)
        simulated_sign_energy_uj = round(avg_sign_ms * power_mw, 3)
        simulated_enc_energy_uj = round(avg_enc_ms * power_mw, 3)

        return {
            "security_level_bits": sec_level,
            "keygen_time_ms": round(sum(keygen_times) / len(keygen_times), 3),
            "sign_time_ms": round(avg_sign_ms, 3),
            "verify_time_ms": round(sum(verify_times) / len(verify_times), 3),
            "key_exchange_time_ms": round(avg_enc_ms, 3),
            "private_key_size_bytes": priv_raw_bytes,
            "public_key_size_bytes": pub_der_bytes,
            "signature_size_bytes": sig_bytes,
            "simulated_energy_sign_uj": simulated_sign_energy_uj,
            "simulated_energy_handshake_uj": simulated_enc_energy_uj
        }

