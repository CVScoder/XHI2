#ifndef HEURISTICS_MANAGER_H
#define HEURISTICS_MANAGER_H

#include <cstdint>
#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <chrono>
#include <cmath>

// Threat levels
enum class ThreatLevel {
    NORMAL = 0,
    ELEVATED = 1,
    CRITICAL = 2
};

// Operational modes
enum class OperationalMode {
    STANDARD = 0,      // Normal XenoCipher
    HARDENED = 1,      // Enhanced rounds
    CHACHA20_AEAD = 2, // ChaCha20-Poly1305 fallback
    SALSA20_AEAD = 3   // Salsa20 fallback
};

// Heuristic metrics container
struct HeuristicMetrics {
    // System metrics
    double entropy;              // 0.0-8.0 bits/byte
    double cpuUsage;            // 0.0-100.0%
    double latency;             // milliseconds
    double jitter;              // ms variance
    double packetLoss;          // 0.0-100.0%
    
    // Security metrics
    uint32_t hmacFailures;      // consecutive failures
    uint32_t decryptFailures;   // consecutive failures
    uint32_t replayAttempts;    // count in window
    uint32_t malformedPackets;  // count in window
    uint32_t timingAnomalies;   // count in window
    
    // Timestamp
    std::chrono::steady_clock::time_point timestamp;
    
    HeuristicMetrics() : 
        entropy(7.5), cpuUsage(20.0), latency(45.0), jitter(5.0), packetLoss(0.0),
        hmacFailures(0), decryptFailures(0), replayAttempts(0), 
        malformedPackets(0), timingAnomalies(0)
    { }
};

// Heuristic thresholds from JSON
struct HeuristicThresholds {
    struct Range {
        double min;
        double max;
    };
    
    Range entropyRange;
    Range latencyRange;
    Range jitterRange;
    Range cpuUsageRange;
    
    uint32_t hmacFailureThreshold;
    uint32_t decryptFailureThreshold;
    uint32_t replayAttemptThreshold;
    uint32_t malformedPacketThreshold;
    uint32_t timingAnomalyThreshold;
    
    uint32_t escalationCycles;      // consecutive violations to escalate
    uint32_t deescalationCycles;    // stable cycles to deescalate
    uint32_t ztmReactionTimeMs;     // ZTM decision latency
};

class HeuristicsManager {
public:
    HeuristicsManager();
    ~HeuristicsManager() = default;
    
    // Load heuristic thresholds from JSON
    bool loadThresholdsFromJSON(const std::string& jsonFilePath);
    
    // Update metrics (non-blocking)
    void updateMetrics(const HeuristicMetrics& metrics);
    
    // Evaluate threat level (returns detected mode)
    OperationalMode evaluateThreatAndSwitchMode();
    
    // Record individual events (thread-safe)
    void recordHmacFailure();
    void recordDecryptFailure();
    void recordReplayAttempt();
    void recordMalformedPacket();
    void recordTimingAnomaly();
    void recordCpuUsage(double usage);
    void recordLatency(double ms);
    void recordEntropy(double bits);
    void recordJitter(double ms);
    void recordPacketLoss(double percent);
    
    // Query state (thread-safe)
    ThreatLevel getCurrentThreatLevel() const;
    OperationalMode getCurrentMode() const;
    HeuristicMetrics getLatestMetrics() const;
    std::string getModeDescription(OperationalMode mode) const;
    bool isZTMActive() const;
    
    // Manual controls
    void forceMode(OperationalMode mode);
    void enableZTM(bool enabled);
    void resetMetrics();
    
private:
    mutable std::mutex metricsMutex;
    
    HeuristicMetrics currentMetrics;
    HeuristicThresholds thresholds;
    
    OperationalMode currentMode;
    ThreatLevel currentThreatLevel;
    bool ztmEnabled;
    
    uint32_t violationCounter;      // consecutive violations
    uint32_t stabilityCounter;      // consecutive stable windows
    uint32_t lastModeChangeTime;    // ms since mode change
    
    // Evaluation logic
    bool metricsExceedThresholds() const;
    void updateThreatLevel();
    void escalateMode();
    void deescalateMode();
    std::string recipeToString(OperationalMode mode) const;
};

#endif // HEURISTICS_MANAGER_H
