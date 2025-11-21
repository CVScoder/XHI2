# XenoCipher Benchmark Suite

Complete benchmarking and integration deliverable for XenoCipher on ESP32, comparing performance against AES, RSA, and ECC.

## Overview

This benchmark suite provides:
- **Performance comparison** of XenoCipher (Normal and ZTM) vs AES-256, RSA-2048, ECC secp256r1
- **Zero-Trust Mode (ZTM)** with full 5-algorithm pipeline: LFSR + Tinkerbell + Transposition + ChaCha20 + Salsa20
- **Adaptive recipe switching** for ZTM modes
- **Comprehensive metrics**: timing, memory, throughput, entropy
- **Python analysis** with statistical summaries and visualizations

## Project Structure

```
examples/benchmark/
├── platformio.ini          # PlatformIO configuration
├── src/
│   └── main.cpp            # Benchmark implementation
├── analyze_benchmarks.py    # Python analysis script
├── config.json.example      # Example configuration
└── README_benchmark.md      # This file
```

## Building and Flashing

### Prerequisites

- PlatformIO installed
- ESP32 development board
- Python 3.7+ with packages: `pandas`, `numpy`, `matplotlib`, `seaborn`, `scipy`

### Build and Upload

```bash
cd examples/benchmark

# Build and upload firmware
pio run -e esp32dev -t upload

# Monitor serial output
pio run -e esp32dev -t monitor

# Upload SPIFFS filesystem (for config and results)
pio run -e esp32dev -t uploadfs
```

### Extract Results

**Method 1: Serial Capture**
```bash
# Capture serial output to file
pio run -e esp32dev -t monitor > benchmark_output.csv

# Filter CSV lines only
grep "^20" benchmark_output.csv > results.csv
```

**Method 2: SPIFFS Download**
```bash
# Use esptool or PlatformIO to download SPIFFS
pio run -e esp32dev -t uploadfs
# Then use SPIFFS tools to extract /benchmark_results.csv
```

## Configuration

### Serial Configuration

The benchmark can be configured via Serial input (future enhancement) or SPIFFS config file.

### SPIFFS Configuration

Create `/config.json` on SPIFFS:

```json
{
  "algorithms": ["xenocipher", "xenocipher_ztm", "aes"],
  "modes": ["normal", "full_stack"],
  "plaintext_size": 256,
  "warmup_iterations": 5,
  "measured_iterations": 50,
  "save_ciphertext_samples": true,
  "ztm_recipe": "full_stack",
  "seed": 0
}
```

### ZTM Recipes

When `algorithm` is `"xenocipher_ztm"`, the following recipes are available:

- **`full_stack`**: All 5 algorithms (LFSR + Tinkerbell + Transposition + ChaCha20 + Salsa20)
- **`chacha_heavy`**: ChaCha20 + LFSR + Tinkerbell
- **`salsa_light`**: Salsa20 + LFSR (lightweight)
- **`chaos_only`**: LFSR + Tinkerbell + Transposition (no stream ciphers)
- **`stream_focus`**: ChaCha20 + Salsa20 + minimal chaos

## Output Format

### CSV Columns

```
timestamp_iso,run_id,iteration,algorithm,mode,plaintext_size,ciphertext_size,
enc_time_us,dec_time_us,heap_before,heap_after,heap_delta,peak_heap,
throughput_bytes_s,ciphertext_entropy_sample,integrity_check
```

### Example Output

```
2025-11-21T10:30:00,1763701634,0,xenocipher,normal,256,32,1250,1180,
250000,248500,-1500,240000,204800.00,4A5B6C7D...,PASS
```

## Python Analysis

### Installation

```bash
pip install pandas numpy matplotlib seaborn scipy
```

### Usage

```bash
python analyze_benchmarks.py results.csv --output-dir benchmark_results
```

### Generated Outputs

- **`encryption_times.png`**: Bar chart with error bars for encryption times
- **`decryption_times.png`**: Bar chart with error bars for decryption times
- **`boxplots.png`**: Boxplots for timing and memory distributions
- **`throughput_vs_size.png`**: Line plot of throughput vs plaintext size
- **`entropy_heatmap.png`**: Heatmap of ciphertext entropy (algorithm × mode)
- **`scatter_ciphertext_vs_time.png`**: Scatter plot of ciphertext size vs time
- **`report.md`**: Markdown summary with recommendations
- **`summary.json`**: JSON summary for dashboard ingestion

## Adaptive Switching Integration

### Dashboard Integration

The benchmark suite includes hooks for adaptive switching from the dashboard:

1. **Mode Toggle**: Switch between Normal and ZTM modes
2. **Recipe Selection**: Choose ZTM recipe (FULL_STACK, CHACHA_HEAVY, etc.)
3. **Telemetry Events**: Algorithm changes and heuristic triggers

### Server Integration

See `examples/benchmark/integration/adaptive_switching.cpp` for server-side hooks.

### ESP32 Integration

The benchmark code includes hooks for:
- Receiving mode/recipe changes via WebSocket or HTTP
- Acknowledging switches before applying
- Emitting telemetry events

## Measurement Guidelines

### Fairness

- Same plaintext input across all algorithms
- Deterministic seeding (configurable) for reproducibility
- Warm-up runs to mitigate cache/JIT effects
- Same key sizes where applicable

### Accuracy

- Uses `esp_timer_get_time()` for microsecond precision
- Uses `esp_get_free_heap_size()` for memory measurements
- Integrity verification: `decrypted == original`

### Entropy Analysis

- Optional ciphertext samples saved for offline analysis
- Shannon entropy computed in Python
- Byte frequency and chi-square tests

## Recommendations

### Resource-Constrained IoT (ESP32)

1. **Normal XenoCipher**: Best balance of security and performance
2. **ZTM with SALSA_LIGHT**: Lower memory footprint
3. **AES-256**: If hardware acceleration available

### High-Security Scenarios

1. **ZTM with FULL_STACK**: All 5 algorithms provide defense in depth
2. **ZTM with CHACHA_HEAVY**: Strong stream cipher with chaos
3. **Adaptive switching**: Based on threat heuristics

## Troubleshooting

### SPIFFS Not Initializing

```cpp
// Check SPIFFS.begin() return value
if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS failed - check partition table");
}
```

### Out of Memory

- Reduce `measured_iterations`
- Reduce `plaintext_size`
- Use lighter ZTM recipes (SALSA_LIGHT)

### Integrity Failures

- Check that decryption is implemented correctly
- Verify key derivation matches encryption
- Check for buffer overflows

## Example Results

See `benchmark_results/` directory for example outputs from a typical run.

## License

Same as main XenoCipher project.

