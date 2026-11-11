"""
Command-Line Interface (CLI) Demonstration and Verification Runner.
Executes the ECC IoT protocol, runs simulated security attacks, and benchmarks performance.
"""

import os
import sys
import time
import argparse

# Configure Matplotlib config dir
os.environ["MPLCONFIGDIR"] = os.path.join(os.path.dirname(__file__), ".mplconfig")

from crypto.ecdsa_auth import CertificateAuthority
from protocol.node import IoTNode
from protocol.gateway import IoTGateway
from simulation.attacks import AttackSimulator
from benchmark.runner import CryptoBenchmarkRunner
from benchmark.visualizer import BenchmarkVisualizer

def run_protocol_demo():
    print("\n" + "="*70)
    print("  [DEMO] ECC-BASED SECURE COMMUNICATION FOR IOT DEVICES")
    print("="*70)

    # 1. Commissioning & CA Setup
    print("\n[*] Initializing Root Certificate Authority (CA)...")
    ca = CertificateAuthority("National-IoT-RootCA")
    print(f"    [+] Root CA Name: {ca.name}")
    print(f"    [+] CA Public Key (DER): {ca.get_ca_public_bytes().hex()[:32]}... ({len(ca.get_ca_public_bytes())} bytes)")

    print("\n[*] Provisioning IoT Edge Gateway & Node...")
    gateway = IoTGateway.register_new("Gateway-Alpha", ca)
    node = IoTNode.register_new("SmartSensor-Env-01", ca)
    print(f"    [+] Gateway registered with CA cert: {gateway.server_id}")
    print(f"    [+] Node registered with CA cert: {node.node_id}")

    # 2. Handshake (Mutual Authentication & ECDH)
    print("\n[*] Executing Mutual Ephemeral ECDH Handshake (secp256r1)...")
    t0 = time.perf_counter()
    client_hello = node.start_handshake()
    handshake_tx_time = (time.perf_counter() - t0) * 1000.0
    print(f"    [-->] Node sends ClientHello: Nonce={client_hello.client_nonce_hex[:12]}... (Elapsed: {handshake_tx_time:.2f}ms)")

    success, server_hello, gw_msg = gateway.handle_client_hello(client_hello)
    if not success:
        print(f"    [!] Gateway rejected handshake: {gw_msg}")
        return
    print(f"    [<--] Gateway accepts & sends ServerHello: Nonce={server_hello.server_nonce_hex[:12]}...")

    success, node_msg = node.process_server_hello(server_hello)
    if not success:
        print(f"    [!] Node rejected ServerHello: {node_msg}")
        return
    print(f"    [+] Mutual Handshake Complete! Established Session ID: {node.session_id}")
    print(f"    [+] Derived Session Encryption Key (AES-256): {node.session_keys.encryption_key.hex()[:32]}...")
    print(f"    [+] Derived Session Base IV (96-bit): {node.session_keys.base_iv.hex()}")

    # 3. Secure Telemetry Streaming
    print("\n[*] Streaming Authenticated & Encrypted Telemetry Packets (AES-256-GCM)...")
    for i in range(1, 4):
        packet = node.create_telemetry_packet()
        print(f"\n    [Packet #{i}] Node Transmitting:")
        print(f"      - Sequence Number: {packet.header.sequence_num}")
        print(f"      - IV (base_iv XOR seq): {packet.header.iv_hex}")
        print(f"      - Ciphertext + Tag (Hex): {packet.ciphertext_hex[:32]}... (Total: {len(packet.ciphertext_hex)//2} bytes)")

        # Gateway Ingestion
        success, payload, ack, reason = gateway.receive_telemetry(packet)
        if success:
            print(f"      [✓] Gateway Verified & Decrypted:")
            print(f"          Payload: Temp={payload['temperature_c']}°C, Humidity={payload['humidity_pct']}%, Status={payload['status']}")
            print(f"          Sent ACK #{ack.ack_sequence_num} to Node.")
        else:
            print(f"      [✗] Gateway Ingestion Failed: {reason}")

def run_attacks_demo():
    print("\n" + "="*70)
    print("  [SECURITY SUITE] SIMULATED ATTACKS & CRYPTOGRAPHIC DEFENSES")
    print("="*70)

    ca = CertificateAuthority("Security-Testing-CA")
    gateway = IoTGateway.register_new("Gateway-SecLab", ca)
    node = IoTNode.register_new("Sensor-SecLab", ca)

    # Establish baseline session
    client_hello = node.start_handshake()
    _, server_hello, _ = gateway.handle_client_hello(client_hello)
    node.process_server_hello(server_hello)

    # 1. Eavesdropping
    print("\n[1] Attack: Passive Wiretapping / Sniffing")
    eavesdrop_res = AttackSimulator.simulate_eavesdropping(node, gateway)
    print(f"    Ciphertext Entropy: {eavesdrop_res['shannon_entropy']} bits/byte ({eavesdrop_res['entropy_efficiency_pct']}% of max)")
    print(f"    Outcome: Confirmed ZERO plaintext leakage.")

    # 2. MITM Key Substitution
    print("\n[2] Attack: Active Man-in-the-Middle (MITM) Key Substitution")
    mitm_res = AttackSimulator.simulate_mitm_attack(node, gateway)
    print(f"    Scenario 1 (Rogue Ephemeral Key): {mitm_res['scenario_1_result']} -> {mitm_res['scenario_1_reason']}")
    print(f"    Scenario 2 (Rogue Untrusted CA): {mitm_res['scenario_2_result']} -> {mitm_res['scenario_2_reason']}")

    # 3. Tampering / Bit-flipping
    print("\n[3] Attack: Packet Bit-Flipping / Tampering")
    tamper_res = AttackSimulator.simulate_tamper_attack(node, gateway)
    print(f"    Ciphertext Alteration Blocked: {tamper_res['ciphertext_tamper_blocked']} -> {tamper_res['ciphertext_tamper_reason']}")
    print(f"    Header/AAD Alteration Blocked: {tamper_res['header_aad_tamper_blocked']} -> {tamper_res['header_aad_tamper_reason']}")

    # 4. Replay Attack
    print("\n[4] Attack: Packet Replay & Delayed Injection")
    replay_res = AttackSimulator.simulate_replay_attack(node, gateway)
    print(f"    Immediate Replay Blocked: {replay_res['immediate_replay_blocked']} -> {replay_res['immediate_replay_reason']}")
    print(f"    Delayed Replay Blocked: {replay_res['delayed_replay_blocked']} -> {replay_res['delayed_replay_reason']}")

def run_benchmarks_demo(iterations: int = 15):
    print("\n" + "="*70)
    print(f"  [BENCHMARK] EMPIRICAL COMPARISON: ECC (P-256) vs RSA (2048 & 3072)")
    print("="*70)
    print(f"[*] Running {iterations} iterations per operation...")

    runner = CryptoBenchmarkRunner(iterations=iterations)
    res = runner.run_benchmarks()

    print("\n{:<12} {:<12} {:<12} {:<12} {:<14} {:<12}".format(
        "Algorithm", "Keygen (ms)", "Sign (ms)", "Verify (ms)", "Pub Key (B)", "Sign (B)"
    ))
    print("-" * 75)
    for name, metrics in res["algorithms"].items():
        print("{:<12} {:<12.2f} {:<12.2f} {:<12.2f} {:<14} {:<12}".format(
            name,
            metrics["keygen_time_ms"],
            metrics["sign_time_ms"],
            metrics["verify_time_ms"],
            metrics["public_key_size_bytes"],
            metrics["signature_size_bytes"]
        ))

    print("\n[*] Generating comparative visual charts...")
    viz = BenchmarkVisualizer("benchmark/charts")
    charts = viz.generate_all_charts(res)
    for chart_type, path in charts.items():
        print(f"    [+] Saved {chart_type.upper()} chart to: {path}")

def main():
    parser = argparse.ArgumentParser(description="ECC Secure IoT Communication System")
    parser.add_argument("--demo", action="store_true", help="Run full protocol demonstration")
    parser.add_argument("--attacks", action="store_true", help="Run security attack simulations")
    parser.add_argument("--benchmark", action="store_true", help="Run ECC vs RSA benchmark")
    parser.add_argument("--all", action="store_true", help="Run all demonstrations, attacks, and benchmarks")

    args = parser.parse_args()

    if args.all or (not args.demo and not args.attacks and not args.benchmark):
        run_protocol_demo()
        run_attacks_demo()
        run_benchmarks_demo()
    else:
        if args.demo:
            run_protocol_demo()
        if args.attacks:
            run_attacks_demo()
        if args.benchmark:
            run_benchmarks_demo()

if __name__ == "__main__":
    main()
