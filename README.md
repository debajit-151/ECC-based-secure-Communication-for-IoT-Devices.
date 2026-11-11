# 🔒 ECC-Based Secure Communication for IoT Devices
> **Applied Cryptography Course Project**  
> Complete implementation of a lightweight, end-to-end Elliptic Curve Cryptography (ECC) secure communication framework for resource-constrained IoT systems.

---

## 🌟 Overview & Key Features

IoT devices (smart sensors, medical telemetry, industrial controllers) are constrained by low computational power, limited battery life, minimal RAM/Flash, and narrow wireless bandwidth. Traditional RSA cryptosystems require 2048-bit or 3072-bit keys, which impose severe CPU latency, excessive energy consumption, and high network packet overhead.

This project implements an **ECC-based hybrid cryptosystem** offering **128-bit security level** (equivalent to RSA-3072) with:
- **7,500× Faster Key Generation** than RSA-3072.
- **5.3× Smaller Digital Signatures** (72 bytes vs 384 bytes).
- **4.6× Smaller Public Keys** (91 bytes vs 422 bytes).
- **29.3× Lower Estimated Microcontroller Energy Consumption**.

### Cryptographic Stack:
- **Asymmetric Curve**: NIST P-256 (`secp256r1`)
- **Key Exchange**: Ephemeral Diffie-Hellman (`ECDHE`) for **Perfect Forward Secrecy (PFS)**
- **Authentication & Non-Repudiation**: Digital Signatures (`ECDSA-SHA256`) + Root Certificate Authority
- **Key Derivation**: `HKDF-SHA256` (RFC 5869)
- **Symmetric Cipher**: `AES-256-GCM` (Authenticated Encryption with Associated Data)
- **Anti-Replay**: Monotonic sequence counters + deterministic IV derivation (`Base_IV ⊕ Seq`) + clock skew freshness validation

---

## 🚀 Quick Start Guide

### 1. Requirements & Installation
The project runs on **Python 3.10+**.

```bash
# Clone or navigate to the repository
cd Applied_Cryptography_Project

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Full CLI Demonstration
Executes the protocol handshake, encrypted telemetry transmission, simulated cyberattacks, and empirical benchmarks:

```bash
python main.py --all
```

*CLI Flags:*
- `python main.py --demo` : Run the protocol handshake and encrypted sensor transmission.
- `python main.py --attacks` : Run the cyberattack simulation lab (MITM, Eavesdropping, Tampering, Replay).
- `python main.py --benchmark` : Run the ECC vs RSA empirical benchmark and generate PNG charts.

### 3. Launch the Interactive Web Dashboard (Streamlit)
To launch the interactive GUI with live packet inspection, attack lab, and telemetry charts:

```bash
streamlit run app.py
```

*Dashboard Tabs:*
1. **📡 Live IoT Telemetry & Network**: Stream real-time encrypted telemetry from simulated IoT nodes to the Gateway.
2. **🔍 Cryptographic Packet Inspector**: View raw hex keys, certificates, ECDHE curve points, and AES-GCM headers/tags.
3. **🛡️ Attack & Defense Security Lab**: Trigger live MITM, bit-flipping, and replay attacks to watch crypto defenses in action.
4. **📊 ECC vs RSA Performance Benchmark**: Run live empirical tests with custom iteration counts and view comparison plots.
5. **📐 Mathematical Foundations (ECDLP)**: Explore the Weierstrass curve equation, point addition/doubling, and ECDLP proofs.

---

## 🧪 Automated Unit Test Suite

Run all automated unit tests covering cryptographic primitives, protocol messages, and attack mitigations:

```bash
python -m unittest discover tests
```

*Output:*
```text
............
----------------------------------------------------------------------
Ran 12 tests in 0.028s

OK
```

---

## 📊 Empirical Benchmark Results

| Metric | ECC (secp256r1) | RSA-2048 | RSA-3072 | ECC Advantage |
| :--- | :--- | :--- | :--- | :--- |
| **Security Strength** | 128-bit level | 112-bit level | 128-bit level | Matches RSA-3072 |
| **Keygen Latency** | **0.02 ms** | 51.28 ms | 151.31 ms | **> 7,500× Faster** |
| **Signing Latency** | **0.03 ms** | 0.46 ms | 0.88 ms | **29× Faster** |
| **Verification Latency** | 0.09 ms | 0.03 ms | 0.06 ms | Constant-time validation |
| **Public Key Size** | **91 Bytes** | 294 Bytes | 422 Bytes | **4.6× Smaller** |
| **Signature Size** | **72 Bytes** | 256 Bytes | 384 Bytes | **5.3× Smaller** |
| **Signing Energy (µJ)** | **0.99 µJ** | 15.18 µJ | 29.04 µJ | **29.3× Lower Energy** |

*Generated benchmark plots are saved to `benchmark/charts/`:*
- `keygen_comparison.png`
- `crypto_operations_time.png`
- `key_and_signature_sizes.png`
- `energy_consumption.png`

---

## 🛡️ Threat Model & Attack Mitigations

Under the **Dolev-Yao adversary model** (attacker controls the communication channel):

1. **Passive Eavesdropping**:
   - Telemetry payload encrypted with AES-256-GCM.
   - Ciphertext exhibits high Shannon entropy (~6.73 bits/byte for short payloads, >90% of theoretical maximum for sample size) with zero plaintext leakage.
2. **Man-In-The-Middle (MITM) Key Substitution**:
   - Ephemeral public keys ($Q_{eph}$) are signed with long-term ECDSA identity keys certified by the Root CA.
   - Rogue key substitution immediately breaks the signature, aborting handshake.
3. **Packet Tampering & Bit-Flipping**:
   - AES-GCM GHASH authentication tag binds both the ciphertext and header (AAD).
   - Any single bit flip in transit causes authentication failure ($p = 2^{-128}$ chance of forgery) and immediate packet rejection.
4. **Replay Attacks**:
   - Gateway enforces monotonic sequence tracking ($\text{Seq} > \text{Last\_Seq}$) and drops duplicate sequence numbers.
   - Clock-skew check drops delayed packets exceeding the 30-second freshness window.

---

## 📁 Repository Structure

```
Applied_Cryptography_Project/
├── config.py                 # Cryptographic and protocol constants
├── crypto/
│   ├── curves.py             # NIST P-256 curve parameters & point verification
│   ├── ecdh.py               # Ephemeral Diffie-Hellman (ECDHE) key agreement
│   ├── ecdsa_auth.py         # ECDSA digital signatures & Certificate Authority
│   ├── kdf.py                # HKDF-SHA256 session key derivation
│   └── aead_cipher.py        # AES-256-GCM authenticated encryption engine
├── protocol/
│   ├── messages.py           # Packet schemas (Handshake, Telemetry, ACK)
│   ├── node.py               # Simulated IoT sensor node
│   └── gateway.py            # IoT Edge Gateway aggregator
├── simulation/
│   └── attacks.py            # Cyberattack simulation suite (MITM, Replay, etc.)
├── benchmark/
│   ├── runner.py             # Empirical benchmark runner
│   ├── visualizer.py         # Matplotlib chart generator
│   └── charts/               # Generated high-resolution comparison plots
├── tests/
│   ├── test_crypto.py        # Unit tests for core crypto primitives
│   ├── test_protocol.py      # Unit tests for protocol messages
│   └── test_attacks.py       # Unit tests proving attack mitigation
├── app.py                    # Streamlit interactive web dashboard
├── main.py                   # CLI demonstration runner
├── requirements.txt          # Python dependencies
├── docs/
│   └── PROJECT_REPORT.md     # Academic project report with mathematical proofs
└── README.md                 # Project documentation
```

---

## 📚 Academic Documentation
For full mathematical derivations, group law equations, ECDLP analysis, and formal security proofs, see [PROJECT_REPORT.md](docs/PROJECT_REPORT.md).
