/**
 * Adaptive Switching Integration Hooks
 * 
 * Provides hooks for dashboard-controlled mode switching and recipe selection.
 * Integrates with existing XenoCipher pipeline without breaking changes.
 */

#ifndef ADAPTIVE_SWITCHING_H
#define ADAPTIVE_SWITCHING_H

#include <cstdint>
#include <string>
#include <functional>

// ZTM Recipe types
enum class ZTMRecipe {
    FULL_STACK,      // All 5: LFSR + Tinkerbell + Transposition + ChaCha20 + Salsa20
    CHACHA_HEAVY,    // ChaCha20 + LFSR + Tinkerbell
    SALSA_LIGHT,     // Salsa20 + LFSR
    CHAOS_ONLY,      // LFSR + Tinkerbell + Transposition (no stream ciphers)
    STREAM_FOCUS     // ChaCha20 + Salsa20 + minimal chaos
};

// Operational mode
enum class OperationalMode {
    NORMAL,          // Standard XenoCipher (3 algorithms)
    ZTM              // Zero-Trust Mode (5 algorithms)
};

// Adaptive switching state
struct AdaptiveState {
    OperationalMode currentMode;
    ZTMRecipe currentRecipe;
    bool modeChangePending;
    bool acknowledged;
    uint32_t lastChangeTimestamp;
    
    AdaptiveState() : 
        currentMode(OperationalMode::NORMAL),
        currentRecipe(ZTMRecipe::FULL_STACK),
        modeChangePending(false),
        acknowledged(false),
        lastChangeTimestamp(0)
    {}
};

// Callback types
using ModeChangeCallback = std::function<void(OperationalMode, ZTMRecipe, bool&)>;
using TelemetryCallback = std::function<void(const std::string&, const std::string&)>;

class AdaptiveSwitcher {
private:
    AdaptiveState state;
    ModeChangeCallback modeChangeCb;
    TelemetryCallback telemetryCb;
    
public:
    AdaptiveSwitcher();
    
    // Request mode change from dashboard
    bool requestModeChange(OperationalMode newMode, ZTMRecipe newRecipe);
    
    // Acknowledge mode change (from ESP32)
    void acknowledgeModeChange();
    
    // Get current state
    const AdaptiveState& getState() const { return state; }
    
    // Set callbacks
    void setModeChangeCallback(ModeChangeCallback cb) { modeChangeCb = cb; }
    void setTelemetryCallback(TelemetryCallback cb) { telemetryCb = cb; }
    
    // Emit telemetry event
    void emitTelemetry(const std::string& event, const std::string& data);
    
    // Parse recipe from string
    static ZTMRecipe parseRecipe(const std::string& recipeStr);
    static std::string recipeToString(ZTMRecipe recipe);
};

#endif // ADAPTIVE_SWITCHING_H

