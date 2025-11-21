#!/usr/bin/env python3
"""
visualize_benchmarks.py

Generate visualizations from ESP32 XenoCipher benchmark results CSV.

Usage:
    python scripts/visualize_benchmarks.py --input <csv_file> [--outdir <output_dir>]

Outputs (saved to output_dir, default 'benchmark_plots'):
- enc_time_<algorithm>.png - Line plot of encryption time per algorithm
- enc_boxplot.png - Box plot comparing encryption times across algorithms
- dec_boxplot.png - Box plot comparing decryption times across algorithms
- throughput_bar.png - Bar chart of mean throughput per algorithm
- heap_delta_boxplot.png - Box plot of heap usage changes per algorithm
- enc_vs_plaintext_scatter.png - Scatter plot of plaintext size vs encryption time
- encryption_vs_decryption.png - Scatter plot comparing encryption vs decryption times
- cpu_freq_over_time.png - CPU frequency changes across measurements
"""

from pathlib import Path
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Set up plotting style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 6)

def load_benchmark_data(csv_path):
    """Load and clean benchmark data from CSV."""
    df = pd.read_csv(csv_path)

    # Convert numeric columns
    numeric_cols = [
        'warmup_iter', 'measured_iter', 'plaintext_size', 'key_size',
        'encrypt_time_us', 'decrypt_time_us', 'heap_before', 'heap_after',
        'heap_diff', 'cpu_freq', 'throughput'
    ]

    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    return df

def plot_enc_time_per_algorithm(df, outdir):
    """Create line plots of encryption time across iterations for each algorithm."""
    algorithms = df['algorithm'].dropna().unique()

    for alg in algorithms:
        subset = df[df['algorithm'] == alg].copy()
        if subset.empty:
            continue

        subset_sorted = subset.sort_values(by='measured_iter')
        x = subset_sorted['measured_iter'].values
        y = subset_sorted['encrypt_time_us'].values

        # Remove NaN values
        valid_idx = ~(np.isnan(x) | np.isnan(y))
        x = x[valid_idx]
        y = y[valid_idx]

        if len(x) == 0:
            continue

        plt.figure(figsize=(12, 6))
        plt.plot(x, y, marker='o', linestyle='-', linewidth=2, markersize=6, alpha=0.7)
        plt.xlabel('Iteration', fontsize=12)
        plt.ylabel('Encryption Time (μs)', fontsize=12)
        plt.title(f'Encryption Time Across Iterations — {alg}', fontsize=14, fontweight='bold')
        plt.grid(True, alpha=0.3)

        fname = outdir / f'enc_time_{alg}.png'
        plt.tight_layout()
        plt.savefig(fname, dpi=200, bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: {fname}")

def plot_encryption_boxplot(df, outdir):
    """Create boxplot comparing encryption times across algorithms."""
    plt.figure(figsize=(10, 6))

    algorithms = sorted(df['algorithm'].dropna().unique())
    data = []
    labels = []

    for alg in algorithms:
        alg_data = df[df['algorithm'] == alg]['encrypt_time_us'].dropna()
        if len(alg_data) > 0:
            data.append(alg_data.values)
            labels.append(alg)

    if data:
        bp = plt.boxplot(data, labels=labels, patch_artist=True, notch=False)

        # Color the boxes
        for patch in bp['boxes']:
            patch.set_facecolor('#3498db')
            patch.set_alpha(0.7)

        plt.ylabel('Encryption Time (μs)', fontsize=12)
        plt.title('Encryption Time Distribution per Algorithm', fontsize=14, fontweight='bold')
        plt.grid(True, axis='y', alpha=0.3)
        plt.xticks(rotation=45, ha='right')

        fname = outdir / 'enc_boxplot.png'
        plt.tight_layout()
        plt.savefig(fname, dpi=200, bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: {fname}")
    else:
        print("⚠ No encryption time data for boxplot")

def plot_decryption_boxplot(df, outdir):
    """Create boxplot comparing decryption times across algorithms."""
    plt.figure(figsize=(10, 6))

    algorithms = sorted(df['algorithm'].dropna().unique())
    data = []
    labels = []

    for alg in algorithms:
        alg_data = df[df['algorithm'] == alg]['decrypt_time_us'].dropna()
        if len(alg_data) > 0:
            data.append(alg_data.values)
            labels.append(alg)

    if data:
        bp = plt.boxplot(data, labels=labels, patch_artist=True, notch=False)

        for patch in bp['boxes']:
            patch.set_facecolor('#e74c3c')
            patch.set_alpha(0.7)

        plt.ylabel('Decryption Time (μs)', fontsize=12)
        plt.title('Decryption Time Distribution per Algorithm', fontsize=14, fontweight='bold')
        plt.grid(True, axis='y', alpha=0.3)
        plt.xticks(rotation=45, ha='right')

        fname = outdir / 'dec_boxplot.png'
        plt.tight_layout()
        plt.savefig(fname, dpi=200, bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: {fname}")
    else:
        print("⚠ No decryption time data for boxplot")

def plot_throughput_bar(df, outdir):
    """Create bar chart of mean throughput per algorithm."""
    mean_throughput = df.groupby('algorithm')['throughput'].mean().dropna().sort_values(ascending=False)

    if not mean_throughput.empty:
        plt.figure(figsize=(10, 6))
        colors = plt.cm.viridis(np.linspace(0, 1, len(mean_throughput)))
        bars = plt.bar(range(len(mean_throughput)), mean_throughput.values, color=colors, alpha=0.8)

        plt.xticks(range(len(mean_throughput)), mean_throughput.index, rotation=45, ha='right')
        plt.ylabel('Mean Throughput (bytes/s)', fontsize=12)
        plt.title('Mean Throughput per Algorithm', fontsize=14, fontweight='bold')
        plt.grid(True, axis='y', alpha=0.3)

        # Add value labels on bars
        for i, bar in enumerate(bars):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height/1e6:.1f}M',
                    ha='center', va='bottom', fontsize=10)

        fname = outdir / 'throughput_bar.png'
        plt.tight_layout()
        plt.savefig(fname, dpi=200, bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: {fname}")
    else:
        print("⚠ No throughput data to plot")

def plot_heap_delta_boxplot(df, outdir):
    """Create boxplot of heap delta (memory usage change) per algorithm."""
    plt.figure(figsize=(10, 6))

    algorithms = sorted(df['algorithm'].dropna().unique())
    data = []
    labels = []

    for alg in algorithms:
        alg_data = df[df['algorithm'] == alg]['heap_diff'].dropna()
        if len(alg_data) > 0:
            data.append(alg_data.values)
            labels.append(alg)

    if data:
        bp = plt.boxplot(data, labels=labels, patch_artist=True)

        for patch in bp['boxes']:
            patch.set_facecolor('#2ecc71')
            patch.set_alpha(0.7)

        plt.ylabel('Heap Delta (bytes)', fontsize=12)
        plt.title('Heap Memory Change Distribution per Algorithm', fontsize=14, fontweight='bold')
        plt.grid(True, axis='y', alpha=0.3)
        plt.xticks(rotation=45, ha='right')

        fname = outdir / 'heap_delta_boxplot.png'
        plt.tight_layout()
        plt.savefig(fname, dpi=200, bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: {fname}")
    else:
        print("⚠ No heap delta data to plot")

def plot_enc_vs_plaintext(df, outdir):
    """Create scatter plot of plaintext size vs encryption time."""
    subset = df[df['encrypt_time_us'].notna() & df['plaintext_size'].notna()].copy()

    if not subset.empty:
        plt.figure(figsize=(10, 6))

        algorithms = subset['algorithm'].unique()
        colors = plt.cm.Set2(np.linspace(0, 1, len(algorithms)))

        for i, alg in enumerate(sorted(algorithms)):
            alg_data = subset[subset['algorithm'] == alg]
            plt.scatter(alg_data['plaintext_size'], alg_data['encrypt_time_us'],
                       label=alg, s=50, alpha=0.6, color=colors[i])

        plt.xlabel('Plaintext Size (bytes)', fontsize=12)
        plt.ylabel('Encryption Time (μs)', fontsize=12)
        plt.title('Encryption Time vs Plaintext Size', fontsize=14, fontweight='bold')
        plt.legend()
        plt.grid(True, alpha=0.3)

        fname = outdir / 'enc_vs_plaintext_scatter.png'
        plt.tight_layout()
        plt.savefig(fname, dpi=200, bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: {fname}")
    else:
        print("⚠ No data for plaintext size scatter plot")

def plot_enc_vs_dec(df, outdir):
    """Create scatter plot comparing encryption vs decryption times."""
    subset = df[df['encrypt_time_us'].notna() & df['decrypt_time_us'].notna()].copy()

    if not subset.empty:
        plt.figure(figsize=(10, 6))

        algorithms = subset['algorithm'].unique()
        colors = plt.cm.Spectral(np.linspace(0, 1, len(algorithms)))

        for i, alg in enumerate(sorted(algorithms)):
            alg_data = subset[subset['algorithm'] == alg]
            plt.scatter(alg_data['encrypt_time_us'], alg_data['decrypt_time_us'],
                       label=alg, s=60, alpha=0.6, color=colors[i])

        plt.xlabel('Encryption Time (μs)', fontsize=12)
        plt.ylabel('Decryption Time (μs)', fontsize=12)
        plt.title('Encryption vs Decryption Time Comparison', fontsize=14, fontweight='bold')
        plt.legend()
        plt.grid(True, alpha=0.3)

        fname = outdir / 'encryption_vs_decryption.png'
        plt.tight_layout()
        plt.savefig(fname, dpi=200, bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: {fname}")
    else:
        print("⚠ No data for encryption vs decryption scatter plot")

def plot_cpu_freq_over_time(df, outdir):
    """Create line plot of CPU frequency changes over measurements."""
    subset = df[df['cpu_freq'].notna()].copy().reset_index(drop=True)

    if len(subset) > 0:
        plt.figure(figsize=(14, 6))

        algorithms = sorted(subset['algorithm'].unique())

        for alg in algorithms:
            alg_data = subset[subset['algorithm'] == alg]
            plt.plot(alg_data.index, alg_data['cpu_freq'], marker='o', label=alg, linewidth=2, alpha=0.7)

        plt.xlabel('Measurement Index', fontsize=12)
        plt.ylabel('CPU Frequency (Hz)', fontsize=12)
        plt.title('CPU Frequency Variation Over Time', fontsize=14, fontweight='bold')
        plt.legend()
        plt.grid(True, alpha=0.3)

        fname = outdir / 'cpu_freq_over_time.png'
        plt.tight_layout()
        plt.savefig(fname, dpi=200, bbox_inches='tight')
        plt.close()
        print(f"✓ Saved: {fname}")
    else:
        print("⚠ No CPU frequency data to plot")

def main(argv=None):
    parser = argparse.ArgumentParser(description='Generate visualizations from benchmark CSV data')
    parser.add_argument('--input', '-i', required=True, help='Path to benchmark CSV file')
    parser.add_argument('--outdir', '-o', default='benchmark_plots', help='Output directory for plots')
    args = parser.parse_args(argv) # Pass argv to parse_args

    csv_path = Path(args.input)
    outdir = Path(args.outdir)

    if not csv_path.exists():
        print(f"❌ Error: File not found: {csv_path}")
        return

    outdir.mkdir(parents=True, exist_ok=True)

    print(f"📊 Loading benchmark data from: {csv_path}")
    df = load_benchmark_data(csv_path)
    print(f"   Loaded {len(df)} records")
    print(f"   Algorithms: {', '.join(df['algorithm'].dropna().unique())}")

    print(f"\n🎨 Generating visualizations...")
    plot_enc_time_per_algorithm(df, outdir)
    plot_encryption_boxplot(df, outdir)
    plot_decryption_boxplot(df, outdir)
    plot_throughput_bar(df, outdir)
    plot_heap_delta_boxplot(df, outdir)
    plot_enc_vs_plaintext(df, outdir)
    plot_enc_vs_dec(df, outdir)
    plot_cpu_freq_over_time(df, outdir)

    print(f"\n✅ All visualizations saved to: {outdir.resolve()}")

if __name__ == '__main__':
    # When running directly in Colab, sys.argv might not contain the desired arguments.
    # We can pass them explicitly to main for easier testing/execution in a notebook.
    # Replace 'path/to/your/benchmark.csv' with the actual path to your CSV file.
    # If you intend to run this script from the command line (e.g., in a terminal or via !python in Colab),
    # you can remove the arguments from the main() call and let it parse sys.argv.
    print("💡 The script expects an '--input' argument. Please replace 'path/to/your/benchmark.csv' below with your actual data file.")
    main(['--input', 'benchmark.csv', '--outdir', 'benchmark_plots'])