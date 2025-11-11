#ifndef ADAPTIVE_SWITCHBOARD_H
#define ADAPTIVE_SWITCHBOARD_H

#include "heuristics_manager.h"
#include "chacha20_impl.h"
#include "salsa20_impl.h"
#include <mutex>
#include <memory>

/**
 * Non-intrusive adapter that wraps existing encryption with adaptive switching
 * WITHOUT modifying original XenoCipher components
 */
class AdaptiveSwitchboard {
public:
    AdaptiveSwitchboard();
    ~AdaptiveSwitchboard() = default;
    
    // Load configuration
    bool initialize(const std::string& heuristicsJsonPath);
    
    // Unified encryption interface (delegates to appropriate algorithm)
    // Returns: cipher length, or 0 on failure
    size_t encrypt(
        const uint8_t* plaintext, size_t ptLen,
        uint8_t* ciphertext,
        const uint8_t* key, size_t keyLen,
        const uint8_t* nonce, size_t nonceLen
    );
    
    // Unified decryption interface
    size_t decrypt(
        const uint8_t* ciphertext, size_t ctLen,
        uint8_t* plaintext,
        const uint8_t* key, size_t keyLen,
        const uint8_t* nonce, size_t nonceLen
    );
    
    // Record metrics for threat evaluation
    void recordMetric(const HeuristicMetrics& metrics);
    void recordEvent(const std::string& eventType);  // "hmac_failure", "decrypt_failure", etc.
    
    // Evaluate threat and update mode
    OperationalMode evaluateAndUpdate();
    
    // Query state
    OperationalMode getCurrentMode() const;
    ThreatLevel getCurrentThreatLevel() const;
    std::string getStatusReport() const;
    bool isZTMActive() const;
    
    // Manual controls
    void forceMode(OperationalMode mode);
    void enableZTM(bool enabled);
    
private:
    std::unique_ptr<HeuristicsManager> heuristics;
    std::unique_ptr<ChaCha20> chacha20;
    std::unique_ptr<Salsa20> salsa20;
    
    mutable std::mutex switchboardMutex;
    
    // Delegates actual encryption to appropriate algorithm
    // NOTE: XenoCipher components remain unmodified
    size_t encryptWithCurrentMode(
        const uint8_t* plaintext, size_t ptLen,
        uint8_t* ciphertext,
        const uint8_t* key, const uint8_t* nonce
    );
    
    size_t decryptWithCurrentMode(
        const uint8_t* ciphertext, size_t ctLen,
        uint8_t* plaintext,
        const uint8_t* key, const uint8_t* nonce
    );
};

#endif // ADAPTIVE_SWITCHBOARD_H
