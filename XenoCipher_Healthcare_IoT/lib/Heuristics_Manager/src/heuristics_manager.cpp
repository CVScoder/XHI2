#include "heuristics_manager.h"
#include <fstream>
#include <iostream>
#include <chrono>

#ifndef ARDUINO
#include <nlohmann/json.hpp>
using json = nlohmann::json;
#endif

HeuristicsManager::HeuristicsManager()
    : currentMode(OperationalMode::STANDARD),
      currentThreatLevel(ThreatLevel::NORMAL),
      ztmEnabled(false),
      violationCounter(0),
      stabilityCounter(0),
      lastModeChangeTime(0) {
    
    // Default thresholds
    thresholds.entropyRange = {7.0, 8.0};
    thresholds.latencyRange = {40, 100};
    thresholds.jitterRange = {0, 15};
    thresholds.cpuUsageRange = {0, 80};
    
    thresholds.hmacFailureThreshold = 5;
    thresholds.decryptFailureThreshold = 5;
    thresholds.replayAttemptThreshold = 3;
    thresholds.malformedPacketThreshold = 10;
    thresholds.timingAnomalyThreshold = 20;
    
    thresholds.escalationCycles = 3;
    thresholds.deescalationCycles = 5;
    thresholds.ztmReactionTimeMs = 2000;
}

bool HeuristicsManager::loadThresholdsFromJSON(const std::string& jsonFilePath) {
    std::lock_guard<std::mutex> lock(metricsMutex);

#ifdef ARDUINO
    (void)jsonFilePath;
    // On device builds, skip JSON parsing and keep defaults.
    return true;
#else
    try {
        std::ifstream file(jsonFilePath);
        if (!file.is_open()) {
            std::cerr << "[-] Failed to open JSON file: " << jsonFilePath << std::endl;
            return false;
        }
        
        json j;
        file >> j;
        
        // Parse entropy range
        thresholds.entropyRange.min = j["heuristics"]["entropy"]["min"].get<double>();
        thresholds.entropyRange.max = j["heuristics"]["entropy"]["max"].get<double>();
        
        // Parse latency range
        thresholds.latencyRange.min = j["heuristics"]["latency"]["min"].get<double>();
        thresholds.latencyRange.max = j["heuristics"]["latency"]["max"].get<double>();
        
        // Parse jitter range
        thresholds.jitterRange.min = j["heuristics"]["jitter"]["min"].get<double>();
        thresholds.jitterRange.max = j["heuristics"]["jitter"]["max"].get<double>();
        
        // Parse CPU usage range
        thresholds.cpuUsageRange.min = j["heuristics"]["cpu_usage"]["min"].get<double>();
        thresholds.cpuUsageRange.max = j["heuristics"]["cpu_usage"]["max"].get<double>();
        
        // Parse security thresholds
        thresholds.hmacFailureThreshold = j["thresholds"]["hmac_failures"].get<uint32_t>();
        thresholds.decryptFailureThreshold = j["thresholds"]["decrypt_failures"].get<uint32_t>();
        thresholds.replayAttemptThreshold = j["thresholds"]["replay_attempts"].get<uint32_t>();
        thresholds.malformedPacketThreshold = j["thresholds"]["malformed_packets"].get<uint32_t>();
        thresholds.timingAnomalyThreshold = j["thresholds"]["timing_anomalies"].get<uint32_t>();
        
        // Parse ZTM parameters
        thresholds.escalationCycles = j["ztm"]["escalation_cycles"].get<uint32_t>();
        thresholds.deescalationCycles = j["ztm"]["deescalation_cycles"].get<uint32_t>();
        thresholds.ztmReactionTimeMs = j["ztm"]["reaction_time_ms"].get<uint32_t>();
        
        std::cout << "[+] Heuristics thresholds loaded from JSON" << std::endl;
        return true;
        
    } catch (const json::exception& e) {
        std::cerr << "[-] JSON parsing error: " << e.what() << std::endl;
        return false;
    }
#endif
}

void HeuristicsManager::updateMetrics(const HeuristicMetrics& metrics) {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMetrics = metrics;
    currentMetrics.timestamp = std::chrono::steady_clock::now();
}

OperationalMode HeuristicsManager::evaluateThreatAndSwitchMode() {
    std::lock_guard<std::mutex> lock(metricsMutex);
    
    bool exceeds = metricsExceedThresholds();
    
    if (exceeds) {
        violationCounter++;
        stabilityCounter = 0;
        
        // Check if we should escalate
        if (violationCounter >= thresholds.escalationCycles) {
            escalateMode();
            violationCounter = 0;
        }
    } else {
        stabilityCounter++;
        violationCounter = 0;
        
        // Check if we should deescalate
        if (stabilityCounter >= thresholds.deescalationCycles && currentMode != OperationalMode::STANDARD) {
            deescalateMode();
            stabilityCounter = 0;
        }
    }
    
    updateThreatLevel();
    return currentMode;
}

bool HeuristicsManager::metricsExceedThresholds() const {
    // Check entropy
    if (currentMetrics.entropy < thresholds.entropyRange.min ||
        currentMetrics.entropy > thresholds.entropyRange.max) {
        return true;
    }
    
    // Check latency
    if (currentMetrics.latency > thresholds.latencyRange.max) {
        return true;
    }
    
    // Check jitter
    if (currentMetrics.jitter > thresholds.jitterRange.max) {
        return true;
    }
    
    // Check CPU usage
    if (currentMetrics.cpuUsage > thresholds.cpuUsageRange.max) {
        return true;
    }
    
    // Check security metrics
    if (currentMetrics.hmacFailures >= thresholds.hmacFailureThreshold ||
        currentMetrics.decryptFailures >= thresholds.decryptFailureThreshold ||
        currentMetrics.replayAttempts >= thresholds.replayAttemptThreshold ||
        currentMetrics.malformedPackets >= thresholds.malformedPacketThreshold ||
        currentMetrics.timingAnomalies >= thresholds.timingAnomalyThreshold) {
        return true;
    }
    
    return false;
}

void HeuristicsManager::escalateMode() {
    OperationalMode nextMode;
    
    switch (currentMode) {
        case OperationalMode::STANDARD:
            nextMode = OperationalMode::HARDENED;
            break;
        case OperationalMode::HARDENED:
            nextMode = OperationalMode::CHACHA20_AEAD;
            break;
        case OperationalMode::CHACHA20_AEAD:
            nextMode = OperationalMode::SALSA20_AEAD;
            break;
        default:
            nextMode = currentMode;
    }
    
    if (nextMode != currentMode) {
        std::cerr << "[!] Escalating to mode: " << recipeToString(nextMode) << std::endl;
        currentMode = nextMode;
        lastModeChangeTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

void HeuristicsManager::deescalateMode() {
    OperationalMode prevMode;
    
    switch (currentMode) {
        case OperationalMode::SALSA20_AEAD:
            prevMode = OperationalMode::CHACHA20_AEAD;
            break;
        case OperationalMode::CHACHA20_AEAD:
            prevMode = OperationalMode::HARDENED;
            break;
        case OperationalMode::HARDENED:
            prevMode = OperationalMode::STANDARD;
            break;
        default:
            prevMode = currentMode;
    }
    
    if (prevMode != currentMode) {
        std::cout << "[+] Deescalating to mode: " << recipeToString(prevMode) << std::endl;
        currentMode = prevMode;
        lastModeChangeTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

void HeuristicsManager::updateThreatLevel() {
    if (currentMode == OperationalMode::SALSA20_AEAD) {
        currentThreatLevel = ThreatLevel::CRITICAL;
    } else if (currentMode == OperationalMode::CHACHA20_AEAD ||
               currentMode == OperationalMode::HARDENED) {
        currentThreatLevel = ThreatLevel::ELEVATED;
    } else {
        currentThreatLevel = ThreatLevel::NORMAL;
    }
}

void HeuristicsManager::recordHmacFailure() {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMetrics.hmacFailures++;
}

void HeuristicsManager::recordDecryptFailure() {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMetrics.decryptFailures++;
}

void HeuristicsManager::recordReplayAttempt() {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMetrics.replayAttempts++;
}

void HeuristicsManager::recordMalformedPacket() {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMetrics.malformedPackets++;
}

void HeuristicsManager::recordTimingAnomaly() {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMetrics.timingAnomalies++;
}

void HeuristicsManager::recordCpuUsage(double usage) {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMetrics.cpuUsage = usage;
}

void HeuristicsManager::recordLatency(double ms) {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMetrics.latency = ms;
}

void HeuristicsManager::recordEntropy(double bits) {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMetrics.entropy = bits;
}

void HeuristicsManager::recordJitter(double ms) {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMetrics.jitter = ms;
}

void HeuristicsManager::recordPacketLoss(double percent) {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMetrics.packetLoss = percent;
}

ThreatLevel HeuristicsManager::getCurrentThreatLevel() const {
    std::lock_guard<std::mutex> lock(metricsMutex);
    return currentThreatLevel;
}

OperationalMode HeuristicsManager::getCurrentMode() const {
    std::lock_guard<std::mutex> lock(metricsMutex);
    return currentMode;
}

HeuristicMetrics HeuristicsManager::getLatestMetrics() const {
    std::lock_guard<std::mutex> lock(metricsMutex);
    return currentMetrics;
}

std::string HeuristicsManager::getModeDescription(OperationalMode mode) const {
    return recipeToString(mode);
}

bool HeuristicsManager::isZTMActive() const {
    std::lock_guard<std::mutex> lock(metricsMutex);
    return ztmEnabled;
}

void HeuristicsManager::forceMode(OperationalMode mode) {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMode = mode;
    updateThreatLevel();
    std::cout << "[*] Mode forced to: " << recipeToString(mode) << std::endl;
}

void HeuristicsManager::enableZTM(bool enabled) {
    std::lock_guard<std::mutex> lock(metricsMutex);
    ztmEnabled = enabled;
    std::cout << "[*] Zero Trust Mode: " << (enabled ? "ENABLED" : "DISABLED") << std::endl;
}

void HeuristicsManager::resetMetrics() {
    std::lock_guard<std::mutex> lock(metricsMutex);
    currentMetrics = HeuristicMetrics();
    violationCounter = 0;
    stabilityCounter = 0;
}

std::string HeuristicsManager::recipeToString(OperationalMode mode) const {
    switch (mode) {
        case OperationalMode::STANDARD:
            return "STANDARD (XenoCipher)";
        case OperationalMode::HARDENED:
            return "HARDENED (XenoCipher+)";
        case OperationalMode::CHACHA20_AEAD:
            return "CHACHA20-POLY1305";
        case OperationalMode::SALSA20_AEAD:
            return "SALSA20";
        default:
            return "UNKNOWN";
    }
}
