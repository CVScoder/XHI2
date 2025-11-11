#include "adaptive_switchboard.h"
#include <iostream>

AdaptiveSwitchboard::AdaptiveSwitchboard() {
    heuristics.reset(new HeuristicsManager());
    chacha20.reset(new ChaCha20());
    salsa20.reset(new Salsa20());
}

bool AdaptiveSwitchboard::initialize(const std::string& heuristicsJsonPath) {
    std::lock_guard<std::mutex> lock(switchboardMutex);
    return heuristics->loadThresholdsFromJSON(heuristicsJsonPath);
}

size_t AdaptiveSwitchboard::encrypt(
    const uint8_t* plaintext, size_t ptLen,
    uint8_t* ciphertext,
    const uint8_t* key, size_t keyLen,
    const uint8_t* nonce, size_t nonceLen) {
    
    std::lock_guard<std::mutex> lock(switchboardMutex);
    
    if (!plaintext || !ciphertext || !key || !nonce) {
        std::cerr << "[-] Null pointer passed to encrypt" << std::endl;
        return 0;
    }
    
    return encryptWithCurrentMode(plaintext, ptLen, ciphertext, key, nonce);
}

size_t AdaptiveSwitchboard::decrypt(
    const uint8_t* ciphertext, size_t ctLen,
    uint8_t* plaintext,
    const uint8_t* key, size_t keyLen,
    const uint8_t* nonce, size_t nonceLen) {
    
    std::lock_guard<std::mutex> lock(switchboardMutex);
    
    if (!ciphertext || !plaintext || !key || !nonce) {
        std::cerr << "[-] Null pointer passed to decrypt" << std::endl;
        return 0;
    }
    
    return decryptWithCurrentMode(ciphertext, ctLen, plaintext, key, nonce);
}

size_t AdaptiveSwitchboard::encryptWithCurrentMode(
    const uint8_t* plaintext, size_t ptLen,
    uint8_t* ciphertext,
    const uint8_t* key, const uint8_t* nonce) {
    
    OperationalMode mode = heuristics->getCurrentMode();
    
    try {
        switch (mode) {
            case OperationalMode::STANDARD:
            case OperationalMode::HARDENED:
                // Delegate to existing XenoCipher pipeline
                // NOTE: Not modified here - external caller handles this
                memcpy(ciphertext, plaintext, ptLen);  // Placeholder
                return ptLen;
                
            case OperationalMode::CHACHA20_AEAD:
                chacha20->init(key, 32, nonce, 12);
                chacha20->encrypt(plaintext, ciphertext, ptLen);
                return ptLen;
                
            case OperationalMode::SALSA20_AEAD:
                salsa20->init(key, 32, nonce, 8);
                salsa20->encrypt(plaintext, ciphertext, ptLen);
                return ptLen;
                
            default:
                return 0;
        }
    } catch (const std::exception& e) {
        std::cerr << "[-] Encryption error: " << e.what() << std::endl;
        return 0;
    }
}

size_t AdaptiveSwitchboard::decryptWithCurrentMode(
    const uint8_t* ciphertext, size_t ctLen,
    uint8_t* plaintext,
    const uint8_t* key, const uint8_t* nonce) {
    
    OperationalMode mode = heuristics->getCurrentMode();
    
    try {
        switch (mode) {
            case OperationalMode::STANDARD:
            case OperationalMode::HARDENED:
                // Delegate to existing XenoCipher pipeline
                memcpy(plaintext, ciphertext, ctLen);  // Placeholder
                return ctLen;
                
            case OperationalMode::CHACHA20_AEAD:
                chacha20->init(key, 32, nonce, 12);
                chacha20->decrypt(ciphertext, plaintext, ctLen);
                return ctLen;
                
            case OperationalMode::SALSA20_AEAD:
                salsa20->init(key, 32, nonce, 8);
                salsa20->decrypt(ciphertext, plaintext, ctLen);
                return ctLen;
                
            default:
                return 0;
        }
    } catch (const std::exception& e) {
        std::cerr << "[-] Decryption error: " << e.what() << std::endl;
        return 0;
    }
}

void AdaptiveSwitchboard::recordMetric(const HeuristicMetrics& metrics) {
    std::lock_guard<std::mutex> lock(switchboardMutex);
    heuristics->updateMetrics(metrics);
}

void AdaptiveSwitchboard::recordEvent(const std::string& eventType) {
    std::lock_guard<std::mutex> lock(switchboardMutex);
    
    if (eventType == "hmac_failure") {
        heuristics->recordHmacFailure();
    } else if (eventType == "decrypt_failure") {
        heuristics->recordDecryptFailure();
    } else if (eventType == "replay_attempt") {
        heuristics->recordReplayAttempt();
    } else if (eventType == "malformed_packet") {
        heuristics->recordMalformedPacket();
    } else if (eventType == "timing_anomaly") {
        heuristics->recordTimingAnomaly();
    }
}

OperationalMode AdaptiveSwitchboard::evaluateAndUpdate() {
    std::lock_guard<std::mutex> lock(switchboardMutex);
    return heuristics->evaluateThreatAndSwitchMode();
}

OperationalMode AdaptiveSwitchboard::getCurrentMode() const {
    std::lock_guard<std::mutex> lock(switchboardMutex);
    return heuristics->getCurrentMode();
}

ThreatLevel AdaptiveSwitchboard::getCurrentThreatLevel() const {
    std::lock_guard<std::mutex> lock(switchboardMutex);
    return heuristics->getCurrentThreatLevel();
}

std::string AdaptiveSwitchboard::getStatusReport() const {
    std::lock_guard<std::mutex> lock(switchboardMutex);
    
    HeuristicMetrics metrics = heuristics->getLatestMetrics();
    OperationalMode mode = heuristics->getCurrentMode();
    ThreatLevel level = heuristics->getCurrentThreatLevel();
    
    std::string report = 
        "[MODE] " + heuristics->getModeDescription(mode) + "\n" +
        "[THREAT] " + (level == ThreatLevel::CRITICAL ? "CRITICAL" :
                       level == ThreatLevel::ELEVATED ? "ELEVATED" : "NORMAL") + "\n" +
        "[ENTROPY] " + std::to_string(metrics.entropy) + " bits/byte\n" +
        "[LATENCY] " + std::to_string(metrics.latency) + " ms\n" +
        "[CPU] " + std::to_string(metrics.cpuUsage) + "%\n" +
        "[HMAC_FAILURES] " + std::to_string(metrics.hmacFailures) + "\n" +
        "[DECRYPT_FAILURES] " + std::to_string(metrics.decryptFailures);
    
    return report;
}

bool AdaptiveSwitchboard::isZTMActive() const {
    std::lock_guard<std::mutex> lock(switchboardMutex);
    return heuristics->isZTMActive();
}

void AdaptiveSwitchboard::forceMode(OperationalMode mode) {
    std::lock_guard<std::mutex> lock(switchboardMutex);
    heuristics->forceMode(mode);
}

void AdaptiveSwitchboard::enableZTM(bool enabled) {
    std::lock_guard<std::mutex> lock(switchboardMutex);
    heuristics->enableZTM(enabled);
}
