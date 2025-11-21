# Integration Notes

## Adaptive Switching Integration

### Server-Side

The server now includes two new endpoints:

1. **POST /adaptive-switch**: Dashboard requests mode/recipe change
   - Body: `{"mode": "normal"|"ztm", "recipe": "full_stack"|"chacha_heavy"|...}`
   - Broadcasts `adaptive_switch_request` via WebSocket to ESP32

2. **POST /adaptive-ack**: ESP32 acknowledges mode change
   - Body: `{"mode": "...", "recipe": "...", "success": true|false}`
   - Broadcasts `adaptive_switch_acknowledged` to dashboard

### ESP32-Side

The ESP32 now:
- Listens for `adaptive_switch_request` WebSocket messages
- Applies mode/recipe changes synchronously
- Sends acknowledgment via WebSocket and HTTP POST
- Emits telemetry events for mode changes

### ZTM Pipeline Integration

When `gCurrentMode == OperationalMode::ZTM`, the encryption pipeline adds:
- **Step 6**: ChaCha20 (if recipe includes it)
- **Step 7**: Salsa20 (if recipe includes it)

These steps are applied after the standard 5-step pipeline (Salt → Pad → LFSR → Tinkerbell → Transposition).

### Recipe Support

- **FULL_STACK**: All 5 algorithms (LFSR + Tinkerbell + Transposition + ChaCha20 + Salsa20)
- **CHACHA_HEAVY**: ChaCha20 + LFSR + Tinkerbell
- **SALSA_LIGHT**: Salsa20 + LFSR
- **CHAOS_ONLY**: LFSR + Tinkerbell + Transposition
- **STREAM_FOCUS**: ChaCha20 + Salsa20 + minimal chaos

## Benchmark Integration

The benchmark suite is located in `examples/benchmark/` and:
- Imports existing XenoCipher libs (no breaking changes)
- Implements AES, RSA, ECC for comparison
- Supports all ZTM recipes
- Logs comprehensive metrics to CSV/JSON
- Python analysis script generates reports and visualizations

## Testing Adaptive Switching

1. Start ESP32 and server
2. Connect dashboard
3. Send POST to `/adaptive-switch`:
   ```json
   {
     "mode": "ztm",
     "recipe": "full_stack"
   }
   ```
4. ESP32 should acknowledge and switch mode
5. Verify encryption uses ZTM pipeline (check logs)

## Notes

- Mode changes are applied synchronously (no queuing)
- ESP32 must acknowledge before server considers switch complete
- ZTM mode only activates additional steps if recipe requires them
- Normal mode always uses 3-algorithm pipeline (LFSR + Tinkerbell + Transposition)

