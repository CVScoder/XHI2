#include "adaptive_switching.h"
#include <chrono>

AdaptiveSwitcher::AdaptiveSwitcher() {
    state = AdaptiveState();
}

bool AdaptiveSwitcher::requestModeChange(OperationalMode newMode, ZTMRecipe newRecipe) {
    if (state.modeChangePending) {
        return false;  // Already have pending change
    }
    
    state.modeChangePending = true;
    state.acknowledged = false;
    
    // Emit telemetry
    emitTelemetry("mode_change_requested", 
                  "mode=" + std::to_string((int)newMode) + 
                  ",recipe=" + recipeToString(newRecipe));
    
    // Call callback if set
    if (modeChangeCb) {
        bool accepted = true;
        modeChangeCb(newMode, newRecipe, accepted);
        if (!accepted) {
            state.modeChangePending = false;
            return false;
        }
    }
    
    return true;
}

void AdaptiveSwitcher::acknowledgeModeChange() {
    if (!state.modeChangePending) {
        return;
    }
    
    // Apply the change
    // Note: In actual implementation, this would be called after ESP32 confirms
    // For now, we assume the change is applied when acknowledged
    
    state.acknowledged = true;
    state.modeChangePending = false;
    
    emitTelemetry("mode_change_acknowledged", 
                  "mode=" + std::to_string((int)state.currentMode) + 
                  ",recipe=" + recipeToString(state.currentRecipe));
}

void AdaptiveSwitcher::emitTelemetry(const std::string& event, const std::string& data) {
    if (telemetryCb) {
        telemetryCb(event, data);
    }
}

ZTMRecipe AdaptiveSwitcher::parseRecipe(const std::string& recipeStr) {
    if (recipeStr == "full_stack") return ZTMRecipe::FULL_STACK;
    if (recipeStr == "chacha_heavy") return ZTMRecipe::CHACHA_HEAVY;
    if (recipeStr == "salsa_light") return ZTMRecipe::SALSA_LIGHT;
    if (recipeStr == "chaos_only") return ZTMRecipe::CHAOS_ONLY;
    if (recipeStr == "stream_focus") return ZTMRecipe::STREAM_FOCUS;
    return ZTMRecipe::FULL_STACK;  // Default
}

std::string AdaptiveSwitcher::recipeToString(ZTMRecipe recipe) {
    switch (recipe) {
        case ZTMRecipe::FULL_STACK: return "full_stack";
        case ZTMRecipe::CHACHA_HEAVY: return "chacha_heavy";
        case ZTMRecipe::SALSA_LIGHT: return "salsa_light";
        case ZTMRecipe::CHAOS_ONLY: return "chaos_only";
        case ZTMRecipe::STREAM_FOCUS: return "stream_focus";
        default: return "full_stack";
    }
}

