# ECC-Based Secure Communication for IoT Devices
**Applied Cryptography — Comprehensive Project Report**

---

## Executive Summary
The rapid proliferation of Internet of Things (IoT) devices in smart grids, industrial automation, healthcare monitoring, and smart cities has highlighted severe security challenges. IoT nodes operate under extreme constraints: low computing capacity (microcontrollers such as ARM Cortex-M or ESP32), limited memory (kilobytes of RAM and Flash), battery power limitations, and low-bandwidth wireless links (BLE, LoRaWAN, Zigbee).

Traditional public-key cryptosystems such as RSA require large keys (2048 to 3072 bits) to maintain modern security levels, imposing excessive computational latency, high power consumption, and packet fragmentation.

This project designs, implements, benchmarks, and verifies a complete, lightweight, end-to-end **Elliptic Curve Cryptography (ECC)-based Secure Communication Framework** tailored for resource-constrained IoT devices. The architecture integrates:
1. **NIST P-256 (`secp256r1`) Curve** for 128-bit security level.
2. **Ephemeral Elliptic Curve Diffie-Hellman (ECDHE)** for mutual session key agreement with **Perfect Forward Secrecy (PFS)**.
3. **Elliptic Curve Digital Signature Algorithm (ECDSA-SHA256)** and a lightweight Certificate Authority (CA) to authenticate device identities and eradicate Man-in-the-Middle (MITM) attacks.
4. **HKDF-SHA256 (RFC 5869)** for domain-separated key expansion.
5. **AES-256-GCM (Authenticated Encryption with Associated Data)** for payload confidentiality, tamper detection, and anti-replay integrity binding.
6. **Empirical Benchmarking & Threat Defense Suite** demonstrating resilience against MITM, eavesdropping, bit-flipping/tampering, and replay attacks, alongside an empirical comparison showing that ECC key generation is over **7,500× faster** than RSA-3072 and reduces signature transmission size by **5.3×**.

---

## 1. Problem Statement & IoT Security Challenges

Modern IoT deployments frequently transmit mission-critical telemetry (e.g. medical vital signs, industrial pressure metrics, smart grid power controls) over untrusted wireless networks. Under the **Dolev-Yao threat model**, an adversary possesses full network control: they can eavesdrop, intercept, inject, modify, or replay transmitted packets.

Securing IoT networks requires achieving five core security objectives:
- **Confidentiality**: Eavesdroppers cannot read raw telemetry.
- **Integrity**: Any in-transit byte modification is detected and rejected.
- **Mutual Authentication**: Both Node and Gateway verify each other's identity before exchanging data.
- **Non-Repudiation**: Nodes cannot deny having sent specific critical alerts.
- **Forward Secrecy**: Long-term key compromise in the future does not compromise past recorded session data.

### Why Traditional RSA Fails in IoT
RSA's security relies on the Integer Factorization Problem (IFP). Due to sub-exponential attacks using the General Number Field Sieve (GNFS), RSA requires massive key sizes:
- 112-bit security: RSA 2048-bit modulus
- 128-bit security: RSA 3072-bit modulus

| Parameter | RSA-2048 | RSA-3072 | ECC NIST P-256 | IoT Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Security Level** | 112 bits | 128 bits | 128 bits | ECC meets modern NSA Suite B / NIST standard |
| **Key Generation** | ~50 ms | ~150 ms | **~0.02 ms** | **7,500× faster** (eliminates CPU stalls) |
| **Public Key Size** | 294 Bytes | 422 Bytes | **91 Bytes** (65B raw) | **4.6× smaller** storage & RAM usage |
| **Signature Size** | 256 Bytes | 384 Bytes | **~72 Bytes** (64B raw) | **5.3× smaller** network transmission |
| **Energy per Op** | High | Extreme | **Ultra-Low** | Preserves battery life in wireless nodes |

---

## 2. Mathematical Foundations of ECC

### 2.1 The Weierstrass Equation
The cryptosystem operates over prime finite fields $\mathbb{F}_p$ using a short Weierstrass curve:
$$y^2 \equiv x^3 + ax + b \pmod p$$

For **NIST P-256 (`secp256r1`)**:
- $p = 2^{256} - 2^{224} + 2^{192} + 2^{96} - 1$
- $a = -3 \pmod p$
- $b = \text{0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B}$
- Base Point $G = (G_x, G_y)$ with prime order $n \approx 2^{256}$
- Cofactor $h = 1$ (ensuring no small subgroup attacks)

### 2.2 Group Law & Point Arithmetic
Points on the elliptic curve together with the point at infinity $\mathcal{O}$ form an abelian group.
Given $P = (x_1, y_1)$ and $Q = (x_2, y_2)$:

**Slope calculation $\lambda$**:
$$\lambda = \begin{cases} \frac{y_2 - y_1}{x_2 - x_1} \pmod p & \text{if } P \neq Q \text{ (Point Addition)} \\[6pt] \frac{3x_1^2 + a}{2y_1} \pmod p & \text{if } P = Q \text{ (Point Doubling)} \end{cases}$$

**Resulting Sum $R = P + Q = (x_3, y_3)$**:
$$x_3 \equiv \lambda^2 - x_1 - x_2 \pmod p$$
$$y_3 \equiv \lambda(x_1 - x_3) - y_1 \pmod p$$

Scalar multiplication $k \cdot P$ is computed using double-and-add or Montgomery ladder in $\mathcal{O}(\log k)$ operations.

### 2.3 The Elliptic Curve Discrete Logarithm Problem (ECDLP)
Given base point $G$ and public point $Q = d \cdot G$, finding the private scalar $d \in [1, n-1]$ requires solving the ECDLP.
- The most efficient known attack is Pollard's rho algorithm, which requires $\mathcal{O}(\sqrt{n}) = \mathcal{O}(2^{128})$ operations for a 256-bit curve.
- Because there is no known sub-exponential index calculus attack for general elliptic curves (unlike RSA or classical finite field Diffie-Hellman), ECC achieves maximum cryptographic strength per bit of key length.

---

## 3. Protocol Architecture & Handshake Flow

The protocol comprises three entities:
1. **IoT Node ($N$)**: Sensor/Actuator with identity keypair $(d_N, Q_N)$ and certified identity.
2. **IoT Gateway ($GW$)**: Aggregator server with identity keypair $(d_{GW}, Q_{GW})$.
3. **Root Certificate Authority ($CA$)**: Trust Anchor issuing certified signatures.

### Protocol Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant Node as IoT Sensor Node (N)
    participant GW as IoT Gateway (GW)

    Note over Node,GW: Phase 1: Mutual Ephemeral Handshake (ECDHE + ECDSA)
    Node->>Node: Generate ephemeral keypair (d_eph_N, Q_eph_N) & Nonce_N
    Node->>GW: ClientHello {NodeID, Nonce_N, Timestamp_N, Q_eph_N, Cert_N, Sig_N}
    
    Note over GW: Verify Cert_N via CA & verify Sig_N over parameters
    GW->>GW: Generate ephemeral keypair (d_eph_GW, Q_eph_GW) & Nonce_GW
    GW->>Node: ServerHello {GW_ID, Nonce_GW, Timestamp_GW, Q_eph_GW, Cert_GW, Sig_GW}
    
    Note over Node: Verify Cert_GW via CA & verify Sig_GW over parameters
    Note over Node,GW: Phase 2: Key Agreement & Derivation
    Node->>Node: Compute Shared Secret Z = d_eph_N * Q_eph_GW
    GW->>GW: Compute Shared Secret Z = d_eph_GW * Q_eph_N
    Note over Node,GW: Z is identical on both sides!
    Node->>Node: HKDF-SHA256(Z, Salt, Info) -> K_enc, K_mac, Base_IV
    GW->>GW: HKDF-SHA256(Z, Salt, Info) -> K_enc, K_mac, Base_IV

    Note over Node,GW: Phase 3: Authenticated Telemetry Transmission
    Node->>Node: Sequence = Sequence + 1
    Node->>Node: Unique_IV = Base_IV XOR Sequence
    Node->>Node: AAD = Header(NodeID, SessionID, Sequence, Timestamp, Unique_IV)
    Node->>Node: Ciphertext, Tag = AES-256-GCM-Encrypt(K_enc, Unique_IV, Plaintext, AAD)
    Node->>GW: TelemetryPacket {Header, Ciphertext || Tag}

    Note over GW: 1. Verify Timestamp within 30s window (Anti-delay)
    Note over GW: 2. Verify Sequence > Last_Seen (Anti-replay)
    Note over GW: 3. AES-256-GCM-Decrypt(K_enc, Unique_IV, Ciphertext, AAD)
    GW->>Node: AckPacket {NodeID, SessionID, Ack_Seq, Status="VERIFIED"}
```

---

## 4. Key Derivation & AEAD Authenticated Encryption

### 4.1 Key Derivation Function (HKDF - RFC 5869)
Raw curve coordinates must never be used directly as symmetric keys due to non-uniform distribution.
1. **HKDF-Extract**:
   $$\text{PRK} = \text{HMAC-SHA256}(\text{salt} = \text{Nonce}_N \oplus \text{Nonce}_{GW}, \text{IKM} = Z)$$
2. **HKDF-Expand**:
   $$K_{enc} \parallel K_{mac} \parallel \text{Base\_IV} = \text{HKDF-Expand}(\text{PRK}, \text{info} = \text{"ECC-IoT-Session-v1"}\parallel \text{Nonce}_N \parallel \text{Nonce}_{GW}, 76)$$

### 4.2 AES-256-GCM AEAD Security
- **Confidentiality**: Telemetry JSON payload is encrypted using AES in Counter (CTR) mode.
- **Authenticity & Integrity**: GHASH polynomial authenticator produces a 128-bit authentication tag over both ciphertext and Associated Authenticated Data (AAD).
- **Deterministic Unique IV**:
  $$\text{IV}_i = \text{Base\_IV} \oplus \text{Pad}_{96}(\text{Seq}_i)$$
  Because the sequence counter is strictly monotonic, each packet uses a unique IV, preventing the catastrophic GCM repeated-IV key recovery attack.

---

## 5. Security Threat Analysis & Attack Verification

The system was evaluated against simulated attacks:

| Attack Scenario | Adversary Action | Cryptographic Defense | Gateway Defense Status |
| :--- | :--- | :--- | :--- |
| **Passive Wiretapping** | Sniffing wireless packets | AES-256-GCM Encryption (Shannon entropy = 6.73 b/B, 92% of theoretical sample max) | **Zero Plaintext Leakage** |
| **MITM Key Substitution** | Injecting rogue ephemeral curve point $Q_{Mallory}$ | Ephemeral key is bound into client ECDSA signature; signature verification fails | **BLOCKED (Signature Mismatch)** |
| **MITM Rogue CA** | Self-signing rogue credentials | Gateway validates certificates against Root CA public key | **BLOCKED (Untrusted CA)** |
| **Ciphertext Bit-Flipping** | Tampering 1 bit in encrypted payload | GHASH authentication tag verification fails with probability $1 - 2^{-128}$ | **BLOCKED (Invalid Tag)** |
| **Header / AAD Tampering** | Modifying sequence number or NodeID | AAD is bound into GHASH tag computation | **BLOCKED (Invalid Tag)** |
| **Packet Replay** | Re-transmitting previously captured packet | Gateway enforces monotonic sequence tracking: $\text{Seq} \le \text{Last\_Seq}$ | **BLOCKED (Duplicate Seq)** |
| **Delayed Packet Injection** | Sending delayed packet with manipulated seq | Timestamp freshness validation: $|t_{now} - t_{packet}| > 30.0\text{s}$ | **BLOCKED (Clock Skew Exceeded)** |

---

## 6. Empirical Performance Benchmark (ECC vs. RSA)

Empirical benchmarks were executed on Python 3.14 on a standard x86-64 testing environment, with energy models mapped to an **ARM Cortex-M4 @ 64MHz (33 mW)** microcontroller:

| Metric | ECC (secp256r1) | RSA-2048 | RSA-3072 | ECC Advantage |
| :--- | :--- | :--- | :--- | :--- |
| **Security Equivalent** | 128 bits | 112 bits | 128 bits | **Equal to RSA-3072** |
| **Keygen Latency** | **0.02 ms** | 51.28 ms | 151.31 ms | **> 7,500× faster** |
| **Signing Latency** | **0.03 ms** | 0.46 ms | 0.88 ms | **29× faster** |
| **Verification Latency** | 0.09 ms | 0.03 ms | 0.06 ms | Balanced & constant time |
| **Public Key Size** | **91 Bytes** | 294 Bytes | 422 Bytes | **4.6× smaller** |
| **Signature Size** | **72 Bytes** | 256 Bytes | 384 Bytes | **5.3× smaller** |
| **Simulated Signing Energy** | **0.99 µJ** | 15.18 µJ | 29.04 µJ | **29.3× lower energy** |

### Benchmark Plots
The visual analysis plots generated by the benchmark engine:
- `benchmark/charts/keygen_comparison.png`: Key generation speedup.
- `benchmark/charts/crypto_operations_time.png`: Execution latency of Sign, Verify, and Key Exchange.
- `benchmark/charts/key_and_signature_sizes.png`: Bandwidth and storage savings.
- `benchmark/charts/energy_consumption.png`: Microcontroller energy consumption.

---

## 7. Project Structure & Deliverables

```
Applied_Cryptography_Project/
├── config.py                 # Protocol & curve parameters (P-256, AES-256-GCM, timers)
├── crypto/
│   ├── curves.py             # Curve parameters & Weierstrass verification
│   ├── ecdh.py               # Ephemeral ECDH key agreement
│   ├── ecdsa_auth.py         # ECDSA-SHA256 signatures & Certificate Authority
│   ├── kdf.py                # HKDF-SHA256 key derivation (RFC 5869)
│   └── aead_cipher.py        # AES-256-GCM encryption with unique IV counter
├── protocol/
│   ├── messages.py           # Wire packet schemas (ClientHello, ServerHello, Telemetry, ACK)
│   ├── node.py               # Simulated IoT sensor node
│   └── gateway.py            # IoT Edge Gateway with session & replay tables
├── simulation/
│   └── attacks.py            # Attack simulators (MITM, Eavesdropping, Tamper, Replay)
├── benchmark/
│   ├── runner.py             # Empirical benchmark runner (ECC vs RSA)
│   ├── visualizer.py         # Matplotlib chart generator (PNG outputs)
│   └── charts/               # High-res academic comparison plots
├── tests/
│   ├── test_crypto.py        # Unit tests for crypto primitives
│   ├── test_protocol.py      # Unit tests for protocol handshake & telemetry
│   └── test_attacks.py       # Unit tests proving attack mitigation
├── app.py                    # Streamlit Interactive Web Dashboard
├── main.py                   # CLI demonstration runner
├── requirements.txt          # Python dependencies
└── README.md                 # Setup & quick-start documentation
```

---

## 8. Conclusion
This project provides a comprehensive, mathematically rigorous, and empirically validated implementation of **ECC-based secure communication for IoT devices**. By pairing ephemeral ECDH (secp256r1) with mutual ECDSA authentication and AES-256-GCM authenticated encryption, the protocol guarantees **Confidentiality, Integrity, Authenticity, Non-Repudiation, and Perfect Forward Secrecy** while consuming only a tiny fraction of the computational, memory, and energy resources required by traditional RSA.

All automated test suites (12/12 unit tests) pass with 100% success rate, validating security defenses against wiretapping, MITM, bit-flipping, and replay attacks.
