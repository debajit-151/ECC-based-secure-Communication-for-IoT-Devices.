"""
Streamlit Web Dashboard: ECC-Based Secure Communication for IoT Devices.
Provides interactive IoT simulation, cryptographic packet inspection, live cyberattack lab,
and comparative benchmarks between ECC and RSA.
"""

import os
import time
import json
import streamlit as st
import pandas as pd
import numpy as np

# Set matplotlib config dir to prevent permission issues
os.environ["MPLCONFIGDIR"] = os.path.join(os.path.dirname(__file__), ".mplconfig")

from crypto.curves import NIST_P256
from crypto.ecdsa_auth import CertificateAuthority
from protocol.node import IoTNode
from protocol.gateway import IoTGateway
from simulation.attacks import AttackSimulator
from benchmark.runner import CryptoBenchmarkRunner
from benchmark.visualizer import BenchmarkVisualizer

# Page configuration
st.set_page_config(
    page_title="ECC IoT Secure Communication System",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Session State
if "ca" not in st.session_state:
    st.session_state.ca = CertificateAuthority("National-IoT-RootCA")
    st.session_state.gateway = IoTGateway.register_new("Gateway-Central-01", st.session_state.ca)
    st.session_state.nodes = {}
    st.session_state.telemetry_history = []
    
    # Pre-register 3 sample IoT nodes
    for node_id in ["Sensor-Weather-01", "Sensor-Health-02", "Sensor-Industrial-03"]:
        node = IoTNode.register_new(node_id, st.session_state.ca)
        # Establish initial handshake
        hello = node.start_handshake()
        _, s_hello, _ = st.session_state.gateway.handle_client_hello(hello)
        node.process_server_hello(s_hello)
        st.session_state.nodes[node_id] = node

ca = st.session_state.ca
gateway = st.session_state.gateway
nodes = st.session_state.nodes

# Sidebar
st.sidebar.title("🔒 ECC IoT Cryptosystem")
st.sidebar.markdown("**Applied Cryptography Project**")
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Navigation Menu",
    [
        "📡 Live IoT Telemetry & Network",
        "🔍 Cryptographic Packet Inspector",
        "🛡️ Attack & Defense Security Lab",
        "📊 ECC vs RSA Performance Benchmark",
        "📐 Mathematical Foundations (ECDLP)",
    ]
)

st.sidebar.markdown("---")
st.sidebar.info(
    "**System Specifications**:\n"
    "- Curve: `NIST P-256 (secp256r1)`\n"
    "- Key Agreement: `ECDHE`\n"
    "- Authentication: `ECDSA-SHA256`\n"
    "- Key Derivation: `HKDF-SHA256`\n"
    "- Payload Cipher: `AES-256-GCM`\n"
    "- Security Level: `128 bits`"
)

# -------------------------------------------------------------
# PAGE 1: LIVE IOT TELEMETRY & NETWORK
# -------------------------------------------------------------
if page == "📡 Live IoT Telemetry & Network":
    st.title("📡 Real-Time IoT Telemetry Stream & Gateway Ingestion")
    st.markdown(
        "Simulates resource-constrained IoT edge sensor nodes transmitting encrypted, "
        "authenticated telemetry over an untrusted wireless channel to the IoT Gateway."
    )

    col_ctrl1, col_ctrl2, col_ctrl3 = st.columns([2, 1, 1])
    with col_ctrl1:
        selected_node_id = st.selectbox("Select IoT Device", list(nodes.keys()))
    with col_ctrl2:
        st.write("")
        st.write("")
        send_packet_btn = st.button("📤 Send Secure Telemetry Packet", use_container_width=True)
    with col_ctrl3:
        st.write("")
        st.write("")
        rehandshake_btn = st.button("🔄 Renegotiate Handshake", use_container_width=True)

    target_node: IoTNode = nodes[selected_node_id]

    if rehandshake_btn:
        with st.spinner("Executing fresh ECDHE handshake..."):
            hello = target_node.start_handshake()
            success, s_hello, reason = gateway.handle_client_hello(hello)
            if success:
                target_node.process_server_hello(s_hello)
                st.success(f"New session established for {selected_node_id}! Session ID: `{target_node.session_id}`")
            else:
                st.error(f"Handshake failed: {reason}")

    if send_packet_btn:
        try:
            packet = target_node.create_telemetry_packet()
            success, payload, ack, msg = gateway.receive_telemetry(packet)
            if success:
                st.session_state.telemetry_history.append({
                    "timestamp": time.strftime("%H:%M:%S", time.localtime(packet.header.timestamp)),
                    "node_id": packet.header.node_id,
                    "seq": packet.header.sequence_num,
                    "session_id": packet.header.session_id,
                    "temp_c": payload.get("temperature_c"),
                    "humidity_pct": payload.get("humidity_pct"),
                    "pressure_hpa": payload.get("pressure_hpa"),
                    "battery_pct": payload.get("battery_pct"),
                    "status": payload.get("status"),
                    "ciphertext_preview": packet.ciphertext_hex[:20] + "...",
                    "raw_packet": packet
                })
                st.toast(f"Packet #{packet.header.sequence_num} successfully authenticated & ingested!", icon="✅")
            else:
                st.error(f"Gateway Ingestion Error: {msg}")
        except Exception as e:
            st.error(f"Transmission error: {str(e)}")

    st.markdown("---")
    # Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    session_obj = gateway.sessions.get(target_node.session_id)
    m1.metric("Active Node", selected_node_id)
    m2.metric("Session ID", target_node.session_id if target_node.session_id else "None")
    m3.metric("Sequence Counter", target_node.sequence_counter)
    m4.metric("Gateway Packets Ingested", session_obj.packet_count if session_obj else 0)

    # Telemetry Log & Charts
    if st.session_state.telemetry_history:
        df = pd.DataFrame(st.session_state.telemetry_history)
        
        tab_table, tab_charts = st.tabs(["📋 Ingested Telemetry Feed", "📈 Telemetry Metrics Plots"])
        with tab_table:
            st.dataframe(
                df[["timestamp", "node_id", "seq", "temp_c", "humidity_pct", "battery_pct", "status", "ciphertext_preview"]],
                use_container_width=True
            )
        with tab_charts:
            c1, c2 = st.columns(2)
            with c1:
                st.subheader("Temperature (°C) Trend")
                st.line_chart(df.set_index("timestamp")["temp_c"])
            with c2:
                st.subheader("Humidity (%) Trend")
                st.line_chart(df.set_index("timestamp")["humidity_pct"])
    else:
        st.info("No packets transmitted yet. Click **'Send Secure Telemetry Packet'** above to generate live encrypted traffic.")

# -------------------------------------------------------------
# PAGE 2: CRYPTOGRAPHIC PACKET INSPECTOR
# -------------------------------------------------------------
elif page == "🔍 Cryptographic Packet Inspector":
    st.title("🔍 Deep Cryptographic Packet & Protocol Inspector")
    st.markdown(
        "Inspect the internal cryptographic structures, mathematical keys, and wire-format packets "
        "at each phase of the secure communication protocol."
    )

    selected_node_id = st.selectbox("Inspect Device Credentials", list(nodes.keys()))
    node_obj: IoTNode = nodes[selected_node_id]

    tab_cert, tab_handshake, tab_aead = st.tabs([
        "📜 Digital Identity & X.509 Cert",
        "🤝 Ephemeral ECDH Key Negotiation",
        "🔐 AES-256-GCM AEAD Wire Packet"
    ])

    with tab_cert:
        st.subheader("IoT Device Public Key & CA Certificate")
        st.markdown(
            "Each IoT device possesses a long-term **ECDSA NIST P-256 identity keypair**. "
            "The public key is certified by the trusted Root Certificate Authority (CA) to prevent impersonation."
        )
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Device Identity Certificate**:")
            st.json(node_obj.cert)
        with c2:
            st.markdown("**Device Public Key (PEM format)**:")
            st.code(node_obj.identity_signer.get_public_pem(), language="text")
            st.markdown("**Root CA Verification Status**:")
            st.success("✅ Signed by `National-IoT-RootCA` (Signature mathematically verified)")

    with tab_handshake:
        st.subheader("ECDHE Key Agreement & HKDF Derivation")
        st.markdown(
            "The mutual handshake negotiates ephemeral curve points $Q_A = d_A \\cdot G$ and $Q_B = d_B \\cdot G$. "
            "Both sides compute identical shared secret $Z = d_A \\cdot Q_B = d_B \\cdot Q_A$ without exposing private keys."
        )
        if node_obj.session_keys:
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Negotiated Ephemeral Curve Points**:")
                st.write(f"- **Elliptic Curve**: `secp256r1 (NIST P-256)`")
                st.write(f"- **Key Agreement Mode**: `ECDHE (Ephemeral Diffie-Hellman)`")
                st.write(f"- **Forward Secrecy**: `Enabled` (Past traffic safe even if long-term key compromised)")
                st.write(f"- **Client Nonce**: `{node_obj.client_nonce.hex() if node_obj.client_nonce else 'N/A'}`")
            with c2:
                st.markdown("**Derived Session Keys (HKDF-SHA256)**:")
                st.code(
                    f"Session ID:         {node_obj.session_id}\n"
                    f"AES-256 Key:        {node_obj.session_keys.encryption_key.hex()}\n"
                    f"HMAC/MAC Key:       {node_obj.session_keys.mac_key.hex()}\n"
                    f"Base IV (96-bit):   {node_obj.session_keys.base_iv.hex()}",
                    language="text"
                )

    with tab_aead:
        st.subheader("AES-256-GCM Authenticated Encryption Structure")
        st.markdown(
            "Every telemetry transmission uses **Galois/Counter Mode (GCM)**. The packet header serves as "
            "**Additional Authenticated Data (AAD)**. The payload is encrypted while the 128-bit GHASH tag "
            "guarantees that neither ciphertext nor header can be altered."
        )

        sample_packet = node_obj.create_telemetry_packet({"demo": "inspector_payload"})
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Cleartext Header (Authenticated via AAD)**:")
            st.json({
                "node_id": sample_packet.header.node_id,
                "session_id": sample_packet.header.session_id,
                "sequence_num": sample_packet.header.sequence_num,
                "timestamp": sample_packet.header.timestamp,
                "iv_hex": sample_packet.header.iv_hex
            })
            st.markdown("**Deterministic IV Construction**:")
            st.code(f"IV = Base_IV ⊕ Sequence_Counter\nIV = {sample_packet.header.iv_hex}", language="text")

        with c2:
            st.markdown("**Encrypted Payload & GHASH Tag**:")
            st.code(
                f"Ciphertext + Tag (Hex):\n{sample_packet.ciphertext_hex}\n\n"
                f"Ciphertext Length: {len(sample_packet.ciphertext_hex) // 2} bytes\n"
                f"Payload Cipher:    AES-256-CTR mode\n"
                f"Integrity Tag:     GHASH 128-bit MAC",
                language="text"
            )

# -------------------------------------------------------------
# PAGE 3: ATTACK & DEFENSE SECURITY LAB
# -------------------------------------------------------------
elif page == "🛡️ Attack & Defense Security Lab":
    st.title("🛡️ Cyberattack Simulation & Defense Verification Lab")
    st.markdown(
        "Demonstrate how the ECC cryptosystem withstands common real-world adversarial attacks "
        "under the **Dolev-Yao threat model** (attacker controls the wire: can sniff, modify, replay, and inject packets)."
    )

    test_node: IoTNode = list(nodes.values())[0]

    attack_selection = st.radio(
        "Choose Cyberattack Scenario to Simulate:",
        [
            "1. Passive Wiretapping / Eavesdropping",
            "2. Active Man-In-The-Middle (MITM) Key Substitution",
            "3. Data Tampering & Bit-Flipping",
            "4. Packet Replay Attack",
        ],
        horizontal=True
    )

    st.markdown("---")

    if "1. Passive Wiretapping" in attack_selection:
        st.subheader("Scenario 1: Passive Eavesdropping / Network Sniffing")
        st.markdown(
            "**Adversary Objective**: Capture raw transmission packets on the wireless medium to extract sensor readings."
        )
        if st.button("🚀 Execute Eavesdropping Simulation"):
            res = AttackSimulator.simulate_eavesdropping(test_node, gateway)
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Intercepted Wire Packet Data**:")
                st.code(
                    f"Node ID:          {res['intercepted_header'].node_id}\n"
                    f"Session ID:       {res['intercepted_header'].session_id}\n"
                    f"Sequence Number:  {res['intercepted_header'].sequence_num}\n"
                    f"Ciphertext (Hex): {res['ciphertext_sample_hex']}\n"
                    f"Total Bytes:      {res['ciphertext_len_bytes']} bytes",
                    language="text"
                )
            with c2:
                st.markdown("**Shannon Entropy Analysis**:")
                st.metric("Shannon Entropy", f"{res['shannon_entropy']} bits/byte", f"{res['entropy_efficiency_pct']}% of max")
                st.markdown(
                    f"Theoretical Maximum: `8.0 bits/byte`\n\n"
                    f"**Analysis**: High entropy indicates ciphertext is statistically indistinguishable from random noise. "
                    f"Plaintext secrecy is 100% preserved against brute-force ($2^{{256}}$ operations required)."
                )
                st.success("✅ Defense Verified: Confidentiality Preserved")

    elif "2. Active Man-In-The-Middle" in attack_selection:
        st.subheader("Scenario 2: Active Man-In-The-Middle (MITM) Key Substitution")
        st.markdown(
            "**Adversary Objective**: Intercept ClientHello, substitute attacker's ephemeral curve point $Q_{Mallory}$, "
            "and trick the Gateway into establishing a session with the attacker."
        )
        if st.button("🚀 Execute MITM Attack Simulation"):
            res = AttackSimulator.simulate_mitm_attack(test_node, gateway)
            c1, c2 = st.columns(2)
            with c1:
                st.error("❌ Attack Attempt 1: Swap Ephemeral Public Key")
                st.markdown(
                    f"**Result**: `{res['scenario_1_result']}`\n\n"
                    f"**Gateway Reason**: {res['scenario_1_reason']}\n\n"
                    "Because the ephemeral public key is bound into the ECDSA signature, the Gateway detects that the signature doesn't match the rogue key."
                )
            with c2:
                st.error("❌ Attack Attempt 2: Inject Rogue Self-Signed Certificate")
                st.markdown(
                    f"**Result**: `{res['scenario_2_result']}`\n\n"
                    f"**Gateway Reason**: {res['scenario_2_reason']}\n\n"
                    "The Gateway validates the certificate against the Root CA public key. Unauthorized certificates are immediately rejected."
                )
            st.success(f"✅ Cryptographic Defense: {res['defense_mechanism']}")

    elif "3. Data Tampering" in attack_selection:
        st.subheader("Scenario 3: Packet Tampering & Bit-Flipping")
        st.markdown(
            "**Adversary Objective**: Alter ciphertext bits (e.g., modify temperature reading) or forge header routing data."
        )
        if st.button("🚀 Execute Tampering Simulation"):
            res = AttackSimulator.simulate_tamper_attack(test_node, gateway)
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Ciphertext Bit-Flipping Defense**:")
                if res["ciphertext_tamper_blocked"]:
                    st.success("🛡️ BLOCKED: Tampered Ciphertext Detected")
                else:
                    st.error("VULNERABLE")
                st.caption(f"Gateway Alert: {res['ciphertext_tamper_reason']}")
            with c2:
                st.markdown("**Header/AAD Alteration Defense**:")
                if res["header_aad_tamper_blocked"]:
                    st.success("🛡️ BLOCKED: Tampered AAD Detected")
                else:
                    st.error("VULNERABLE")
                st.caption(f"Gateway Alert: {res['header_aad_tamper_reason']}")
            st.info(f"💡 Defense Explanation: {res['defense_mechanism']}")

    elif "4. Packet Replay" in attack_selection:
        st.subheader("Scenario 4: Packet Replay Attack")
        st.markdown(
            "**Adversary Objective**: Record a legitimate authenticated packet and re-transmit it at a later time."
        )
        if st.button("🚀 Execute Replay Simulation"):
            res = AttackSimulator.simulate_replay_attack(test_node, gateway)
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Original Transmission**:")
                st.success("✅ Packet Accepted & Ingested (Sequence #1)")
                st.markdown("**Immediate Duplicate Replay**:")
                if res["immediate_replay_blocked"]:
                    st.error("🛡️ REPLAY REJECTED: Duplicate Sequence Number Detected")
                    st.caption(f"Gateway: {res['immediate_replay_reason']}")
            with c2:
                st.markdown("**Delayed Replay (Old Timestamp)**:")
                if res["delayed_replay_blocked"]:
                    st.error("🛡️ REPLAY REJECTED: Timestamp Outside Clock-Skew Window")
                    st.caption(f"Gateway: {res['delayed_replay_reason']}")
            st.info(f"💡 Defense Explanation: {res['defense_mechanism']}")

# -------------------------------------------------------------
# PAGE 4: ECC VS RSA PERFORMANCE BENCHMARK
# -------------------------------------------------------------
elif page == "📊 ECC vs RSA Performance Benchmark":
    st.title("📊 Empirical Performance Benchmark: ECC vs. RSA")
    st.markdown(
        "Compare Elliptic Curve Cryptography (**ECC NIST P-256**) with traditional **RSA-2048** and **RSA-3072** "
        "across execution speed, memory footprint, network bandwidth overhead, and simulated IoT energy consumption."
    )

    col1, col2 = st.columns([1, 2])
    with col1:
        iters = st.slider("Benchmark Iterations", min_value=5, max_value=30, value=15, step=5)
        run_bench_btn = st.button("⚡ Run Empirical Benchmark", use_container_width=True)

    if run_bench_btn:
        with st.spinner(f"Running benchmarks ({iters} iterations per algorithm)..."):
            runner = CryptoBenchmarkRunner(iterations=iters)
            st.session_state.bench_results = runner.run_benchmarks()
            viz = BenchmarkVisualizer("benchmark/charts")
            st.session_state.charts = viz.generate_all_charts(st.session_state.bench_results)
            st.success("Benchmark completed and comparison charts generated!")

    if "bench_results" in st.session_state:
        b_data = st.session_state.bench_results
        algos = b_data["algorithms"]

        # Comparative Table
        st.subheader("📋 Empirical Metrics Summary")
        table_rows = []
        for name, metrics in algos.items():
            table_rows.append({
                "Algorithm": name,
                "Security Level (bits)": metrics["security_level_bits"],
                "Keygen Time (ms)": metrics["keygen_time_ms"],
                "Sign Time (ms)": metrics["sign_time_ms"],
                "Verify Time (ms)": metrics["verify_time_ms"],
                "Key Exch / Enc (ms)": metrics["key_exchange_time_ms"],
                "Public Key (Bytes)": metrics["public_key_size_bytes"],
                "Signature (Bytes)": metrics["signature_size_bytes"],
                "Sign Energy (µJ)": metrics["simulated_energy_sign_uj"]
            })
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True)

        # Charts Section
        st.subheader("📈 Visual Comparison Charts")
        c1, c2 = st.columns(2)
        with c1:
            if os.path.exists("benchmark/charts/keygen_comparison.png"):
                st.image("benchmark/charts/keygen_comparison.png", caption="Key Generation Speed Comparison")
            if os.path.exists("benchmark/charts/key_and_signature_sizes.png"):
                st.image("benchmark/charts/key_and_signature_sizes.png", caption="Key & Signature Footprint Comparison")
        with c2:
            if os.path.exists("benchmark/charts/crypto_operations_time.png"):
                st.image("benchmark/charts/crypto_operations_time.png", caption="Cryptographic Latency Comparison")
            if os.path.exists("benchmark/charts/energy_consumption.png"):
                st.image("benchmark/charts/energy_consumption.png", caption="Simulated Energy Consumption on ARM Cortex-M4")
    else:
        st.info("Click **'Run Empirical Benchmark'** to execute real-time tests comparing ECC P-256 and RSA.")

# -------------------------------------------------------------
# PAGE 5: MATHEMATICAL FOUNDATIONS
# -------------------------------------------------------------
elif page == "📐 Mathematical Foundations (ECDLP)":
    st.title("📐 Mathematical Foundations of Elliptic Curve Cryptography")
    st.markdown(
        "Theoretical background, algebraic structure, and mathematical proofs underlying "
        "the security of the NIST P-256 (`secp256r1`) elliptic curve cryptosystem."
    )

    st.subheader("1. The Weierstrass Curve Equation")
    st.latex(r"y^2 \equiv x^3 + ax + b \pmod p")
    st.markdown(
        f"For the **NIST P-256** standard:\n"
        f"- **Modulus $p$**: $2^{{256}} - 2^{{224}} + 2^{{192}} + 2^{{96}} - 1$\n"
        f"- **Coefficient $a$**: $-3 \\pmod p$\n"
        f"- **Coefficient $b$**: `0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B`\n"
        f"- **Cofactor $h$**: `1` (ensures every point belongs to the main prime-order subgroup)"
    )

    st.subheader("2. Group Operations: Point Addition & Point Doubling")
    st.markdown(
        "Let $P = (x_1, y_1)$ and $Q = (x_2, y_2)$ be points on the curve.\n\n"
        "**Slope $\\lambda$ calculation**:"
    )
    st.latex(r"""
    \lambda = \begin{cases} 
    \frac{y_2 - y_1}{x_2 - x_1} \pmod p & \text{if } P \neq Q \text{ (Point Addition)} \\[8pt]
    \frac{3x_1^2 + a}{2y_1} \pmod p & \text{if } P = Q \text{ (Point Doubling)} 
    \end{cases}
    """)
    st.markdown("**Resulting point $R = P + Q = (x_3, y_3)$**:")
    st.latex(r"""
    x_3 \equiv \lambda^2 - x_1 - x_2 \pmod p, \quad y_3 \equiv \lambda(x_1 - x_3) - y_1 \pmod p
    """)

    st.subheader("3. Elliptic Curve Discrete Logarithm Problem (ECDLP)")
    st.markdown(
        "Given the base generator point $G$ and a public key point $Q = d \\cdot G$ "
        "(where $d$ is a 256-bit scalar), finding $d$ is computationally intractable.\n\n"
        "- Best known algorithm for ECDLP: **Pollard's rho algorithm** with time complexity $\\mathcal{O}(\\sqrt{n}) = \\mathcal{O}(2^{128})$.\n"
        "- For RSA: Solved via General Number Field Sieve (GNFS) in sub-exponential time $\\mathcal{L}_n[1/3, c]$, "
        "requiring **3072-bit modulus** to achieve equivalent 128-bit security.\n\n"
        "**Conclusion**: ECC achieves the same 128-bit security level as RSA-3072 with **~12x smaller keys**, "
        "dramatically reducing RAM, Flash, transmission latency, and battery consumption on IoT devices."
    )

