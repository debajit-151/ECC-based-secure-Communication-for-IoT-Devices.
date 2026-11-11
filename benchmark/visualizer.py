"""
Chart Generator for Benchmark Visualization.
Produces high-resolution academic plots comparing ECC vs RSA.
"""

import os
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, Any

class BenchmarkVisualizer:
    """Generates visual comparison charts for academic presentations and reports."""

    def __init__(self, output_dir: str = "benchmark/charts"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        # Configure style
        plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")

    def generate_all_charts(self, benchmark_data: Dict[str, Any]) -> Dict[str, str]:
        """Generates all comparison charts and returns paths to saved image files."""
        algos = benchmark_data["algorithms"]
        saved_files = {}

        saved_files["keygen"] = self.plot_keygen_comparison(algos)
        saved_files["latency"] = self.plot_operation_latencies(algos)
        saved_files["sizes"] = self.plot_size_comparison(algos)
        saved_files["energy"] = self.plot_energy_consumption(algos)

        return saved_files

    def plot_keygen_comparison(self, algos: Dict[str, Dict[str, Any]]) -> str:
        """Bar chart comparing Key Generation Time."""
        fig, ax = plt.subplots(figsize=(8, 5))
        names = list(algos.keys())
        keygen_times = [algos[k]["keygen_time_ms"] for k in names]
        colors = ["#2ecc71", "#3498db", "#e74c3c"]

        bars = ax.bar(names, keygen_times, color=colors, width=0.5, edgecolor="black", linewidth=1.2)
        ax.set_ylabel("Key Generation Time (milliseconds)", fontsize=12, fontweight="bold")
        ax.set_title("Key Generation Speed: ECC (P-256) vs RSA (2048 & 3072)\n(Lower is better)", fontsize=13, fontweight="bold", pad=15)
        ax.grid(axis="y", linestyle="--", alpha=0.7)

        for bar in bars:
            height = bar.get_height()
            ax.annotate(f"{height:.2f} ms",
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 4),
                        textcoords="offset points",
                        ha="center", va="bottom", fontsize=11, fontweight="bold")

        fig.tight_layout()
        out_path = os.path.join(self.output_dir, "keygen_comparison.png")
        fig.savefig(out_path, dpi=200)
        plt.close(fig)
        return out_path

    def plot_operation_latencies(self, algos: Dict[str, Dict[str, Any]]) -> str:
        """Grouped bar chart comparing Sign, Verify, and Key Exchange/Encapsulation."""
        fig, ax = plt.subplots(figsize=(10, 5.5))
        names = list(algos.keys())
        x = np.arange(len(names))
        width = 0.25

        sign_times = [algos[k]["sign_time_ms"] for k in names]
        verify_times = [algos[k]["verify_time_ms"] for k in names]
        exchange_times = [algos[k]["key_exchange_time_ms"] for k in names]

        rects1 = ax.bar(x - width, sign_times, width, label="Signing Latency", color="#3498db", edgecolor="black")
        rects2 = ax.bar(x, verify_times, width, label="Verification Latency", color="#2ecc71", edgecolor="black")
        rects3 = ax.bar(x + width, exchange_times, width, label="Key Exchange / Encapsulation", color="#e67e22", edgecolor="black")

        ax.set_ylabel("Execution Time (milliseconds)", fontsize=12, fontweight="bold")
        ax.set_title("Cryptographic Operation Latencies on IoT Edge\n(Lower is better)", fontsize=13, fontweight="bold", pad=15)
        ax.set_xticks(x)
        ax.set_xticklabels(names, fontsize=11, fontweight="bold")
        ax.legend(frameon=True, fontsize=10)
        ax.grid(axis="y", linestyle="--", alpha=0.7)

        fig.tight_layout()
        out_path = os.path.join(self.output_dir, "crypto_operations_time.png")
        fig.savefig(out_path, dpi=200)
        plt.close(fig)
        return out_path

    def plot_size_comparison(self, algos: Dict[str, Dict[str, Any]]) -> str:
        """Compares Public Key and Digital Signature payload sizes (Bandwidth & Storage)."""
        fig, ax = plt.subplots(figsize=(9, 5))
        names = list(algos.keys())
        x = np.arange(len(names))
        width = 0.35

        pub_sizes = [algos[k]["public_key_size_bytes"] for k in names]
        sig_sizes = [algos[k]["signature_size_bytes"] for k in names]

        b1 = ax.bar(x - width/2, pub_sizes, width, label="Public Key Size (Bytes)", color="#9b59b6", edgecolor="black")
        b2 = ax.bar(x + width/2, sig_sizes, width, label="Signature Size (Bytes)", color="#f39c12", edgecolor="black")

        ax.set_ylabel("Footprint Size (Bytes)", fontsize=12, fontweight="bold")
        ax.set_title("Memory & Transmission Overhead: Key & Signature Sizes\n(Lower is better for IoT)", fontsize=13, fontweight="bold", pad=15)
        ax.set_xticks(x)
        ax.set_xticklabels(names, fontsize=11, fontweight="bold")
        ax.legend(frameon=True, fontsize=10)
        ax.grid(axis="y", linestyle="--", alpha=0.7)

        for bar in b1:
            ax.annotate(f"{bar.get_height()} B", (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=10)
        for bar in b2:
            ax.annotate(f"{bar.get_height()} B", (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=10)

        fig.tight_layout()
        out_path = os.path.join(self.output_dir, "key_and_signature_sizes.png")
        fig.savefig(out_path, dpi=200)
        plt.close(fig)
        return out_path

    def plot_energy_consumption(self, algos: Dict[str, Dict[str, Any]]) -> str:
        """Simulated Microcontroller Energy Consumption."""
        fig, ax = plt.subplots(figsize=(8, 5))
        names = list(algos.keys())
        energy_vals = [algos[k]["simulated_energy_sign_uj"] for k in names]
        colors = ["#16a085", "#2980b9", "#c0392b"]

        bars = ax.bar(names, energy_vals, color=colors, width=0.5, edgecolor="black", linewidth=1.2)
        ax.set_ylabel("Simulated Energy Consumption (Microjoules - µJ)", fontsize=11, fontweight="bold")
        ax.set_title("Simulated Signing Energy on ARM Cortex-M4 (33mW @ 64MHz)\n(Lower is better)", fontsize=12, fontweight="bold", pad=15)
        ax.grid(axis="y", linestyle="--", alpha=0.7)

        for bar in bars:
            height = bar.get_height()
            ax.annotate(f"{height:.2f} µJ",
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 4),
                        textcoords="offset points",
                        ha="center", va="bottom", fontsize=10, fontweight="bold")

        fig.tight_layout()
        out_path = os.path.join(self.output_dir, "energy_consumption.png")
        fig.savefig(out_path, dpi=200)
        plt.close(fig)
        return out_path
