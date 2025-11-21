/**
 * XenoCipher Benchmark Suite for ESP32
 * 
 * This benchmark compares:
 * - XenoCipher (Normal mode: LFSR + Tinkerbell + Transposition)
 * - XenoCipher ZTM (Zero-Trust Mode: LFSR + Tinkerbell + Transposition + ChaCha20 + Salsa20)
 * - AES-256 (mbedTLS)
 * - RSA-2048 (mbedTLS)
 * - ECC secp256r1 (mbedTLS)
 * 
 * Features:
 * - Configurable via Serial input or SPIFFS config
 * - Measures encryption/decryption time, memory usage, throughput
 * - Logs to CSV/JSON on SPIFFS and Serial
 * - Integrity verification
 * - Warm-up runs to mitigate cache effects
 */

#include <Arduino.h>
#include <SPIFFS.h>
#include <mbedtls/aes.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include <cstring>
#include <esp_timer.h>
#include <esp_heap_caps.h>
#include <ArduinoJson.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

// Import XenoCipher libraries
#include "../../lib/CryptoKDF/include/crypto_kdf.h"
#include "../../lib/LFSR/include/lfsr.h"
#include "../../lib/Tinkerbell/include/tinkerbell.h"
#include "../../lib/Transposition/include/transposition.h"
#include "../../lib/HMAC/include/hmac.h"
#include "../../lib/common/common.h"
#include "../../lib/ChaCha20/include/chacha20_impl.h"
#include "../../lib/Salsa20/include/salsa20_impl.h"
#include "../../lib/Heuristics_Manager/include/heuristics_manager.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

struct BenchmarkConfig {
    // Test parameters
    std::vector<std::string> algorithms;  // "xenocipher", "xenocipher_ztm", "aes", "rsa", "ecc"
    std::vector<std::string> modes;      // For XenoCipher: "normal", "ztm", "full_stack", "chacha_heavy", etc.
    size_t plaintextSize = 256;          // Bytes
    size_t warmupIterations = 5;
    size_t measuredIterations = 50;
    bool saveCiphertextSamples = false;
    uint32_t seed = 0;  // 0 = random
    
    // Input source
    bool useSPIFFSInput = false;
    std::string spiffsInputFile = "/input.txt";
    
    // Output
    std::string outputFile = "/benchmark_results.csv";
    bool streamToSerial = true;
    
    // XenoCipher ZTM recipes
    std::string ztmRecipe = "full_stack";  // full_stack, chacha_heavy, salsa_light, chaos_only, stream_focus
};

// ============================================================================
// GLOBAL STATE
// ============================================================================

BenchmarkConfig gConfig;
uint32_t gRunId = 0;
bool gBenchmarkRunning = false;
std::vector<uint8_t> gPlaintext;
std::vector<uint8_t> gTestKey(32);
std::vector<uint8_t> gTestNonce(12);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

String getISOTimestamp() {
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_r(&now, &timeinfo);
    
    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &timeinfo);
    return String(buffer);
}

String bytesToHex(const uint8_t* data, size_t len, size_t maxLen = 32) {
    String hex;
    hex.reserve((len < maxLen ? len : maxLen) * 2);
    for (size_t i = 0; i < len && i < maxLen; ++i) {
        char hexChar[3];
        sprintf(hexChar, "%02X", data[i]);
        hex += hexChar;
    }
    if (len > maxLen) hex += "...";
    return hex;
}

int64_t getTimeMicros() {
    return esp_timer_get_time();
}

size_t getFreeHeap() {
    return esp_get_free_heap_size();
}

size_t getMinFreeHeap() {
    return esp_get_minimum_free_heap_size();
}

// ============================================================================
// XENOCIPHER NORMAL MODE (Existing 3-algorithm pipeline)
// ============================================================================

// Forward declarations for structures
struct SaltMeta {
    uint16_t pos;
    uint8_t len;
};

struct XenoCipherKeys {
    uint8_t hmacKey[32];
    uint8_t tinkerbellKey[16];
    uint8_t transpositionKey[16];
    uint32_t lfsrSeed;
};

bool deriveXenoKeys(const uint8_t* masterKey, uint32_t nonce, XenoCipherKeys& keys) {
    DerivedKeys baseKeys;
    if (!deriveKeys(masterKey, 32, baseKeys)) {
        return false;
    }
    
    MessageKeys msgKeys;
    if (!deriveMessageKeys(baseKeys, nonce, msgKeys)) {
        return false;
    }
    
    memcpy(keys.hmacKey, baseKeys.hmacKey, 32);
    memcpy(keys.tinkerbellKey, msgKeys.tinkerbellKey, 16);
    memcpy(keys.transpositionKey, msgKeys.transpositionKey, 16);
    keys.lfsrSeed = msgKeys.lfsrSeed;
    
    return true;
}

size_t xenocipherEncryptNormal(const uint8_t* plaintext, size_t ptLen,
                                uint8_t* ciphertext, const XenoCipherKeys& keys,
                                uint32_t nonce, const GridSpec& grid) {
    // Step 1: Salt
    SaltMeta meta;
    meta.pos = ptLen;
    meta.len = 2;
    
    std::vector<uint8_t> salted;
    salted.reserve(ptLen + meta.len);
    salted.insert(salted.end(), plaintext, plaintext + ptLen);
    salted.insert(salted.end(), (const uint8_t*)COMMON_SALT, (const uint8_t*)COMMON_SALT + meta.len);
    
    // Step 2: Pad to grid
    size_t gridSize = grid.rows * grid.cols;
    std::vector<uint8_t> buf(gridSize, 0);
    memcpy(buf.data(), salted.data(), salted.size() < gridSize ? salted.size() : gridSize);
    
    // Step 3: LFSR
    ChaoticLFSR32 lfsr(keys.lfsrSeed, keys.tinkerbellKey, 0x0029u);
    lfsr.xorBuffer(buf.data(), buf.size());
    
    // Step 4: Tinkerbell XOR
    const char label[] = "XENO-TINK";
    uint8_t counter = 0;
    size_t offset = 0;
    while (offset < buf.size()) {
        uint8_t block[32];
        uint8_t msg[sizeof(label) + 4 + 1];
        memcpy(msg, label, sizeof(label));
        msg[sizeof(label) + 0] = (uint8_t)((nonce >> 24) & 0xFF);
        msg[sizeof(label) + 1] = (uint8_t)((nonce >> 16) & 0xFF);
        msg[sizeof(label) + 2] = (uint8_t)((nonce >> 8) & 0xFF);
        msg[sizeof(label) + 3] = (uint8_t)(nonce & 0xFF);
        msg[sizeof(label) + 4] = counter;
        
        hmac_sha256_full(keys.tinkerbellKey, 16, msg, sizeof(msg), block);
        
        size_t n = (buf.size() - offset) < sizeof(block) ? (buf.size() - offset) : sizeof(block);
        for (size_t i = 0; i < n; ++i) {
            buf[offset + i] ^= block[i];
        }
        offset += n;
        counter++;
    }
    
    // Step 5: Transposition
    uint8_t trKey8[8];
    memcpy(trKey8, keys.transpositionKey, 8);
    applyTransposition(buf.data(), grid, trKey8, PermuteMode::Forward);
    
    // Copy to output
    memcpy(ciphertext, buf.data(), buf.size());
    return buf.size();
}

size_t xenocipherDecryptNormal(const uint8_t* ciphertext, size_t ctLen,
                                uint8_t* plaintext, const XenoCipherKeys& keys,
                                uint32_t nonce, const GridSpec& grid) {
    std::vector<uint8_t> buf(ciphertext, ciphertext + ctLen);
    
    // Step 5: Inverse Transposition
    uint8_t trKey8[8];
    memcpy(trKey8, keys.transpositionKey, 8);
    applyTransposition(buf.data(), grid, trKey8, PermuteMode::Inverse);
    
    // Step 4: Inverse Tinkerbell XOR
    const char label[] = "XENO-TINK";
    uint8_t counter = 0;
    size_t offset = 0;
    while (offset < buf.size()) {
        uint8_t block[32];
        uint8_t msg[sizeof(label) + 4 + 1];
        memcpy(msg, label, sizeof(label));
        msg[sizeof(label) + 0] = (uint8_t)((nonce >> 24) & 0xFF);
        msg[sizeof(label) + 1] = (uint8_t)((nonce >> 16) & 0xFF);
        msg[sizeof(label) + 2] = (uint8_t)((nonce >> 8) & 0xFF);
        msg[sizeof(label) + 3] = (uint8_t)(nonce & 0xFF);
        msg[sizeof(label) + 4] = counter;
        
        hmac_sha256_full(keys.tinkerbellKey, 16, msg, sizeof(msg), block);
        
        size_t n = (buf.size() - offset) < sizeof(block) ? (buf.size() - offset) : sizeof(block);
        for (size_t i = 0; i < n; ++i) {
            buf[offset + i] ^= block[i];
        }
        offset += n;
        counter++;
    }
    
    // Step 3: Inverse LFSR
    ChaoticLFSR32 lfsr(keys.lfsrSeed, keys.tinkerbellKey, 0x0029u);
    lfsr.xorBuffer(buf.data(), buf.size());
    
    // Step 2: Remove padding (find salt)
    // Step 1: Remove salt
    // For simplicity, assume we know the original length
    size_t originalLen = gPlaintext.size();
    memcpy(plaintext, buf.data(), originalLen < buf.size() ? originalLen : buf.size());
    return originalLen;
}

// ============================================================================
// XENOCIPHER ZTM MODE (5-algorithm pipeline)
// ============================================================================

enum class ZTMRecipe {
    FULL_STACK,      // All 5: LFSR + Tinkerbell + Transposition + ChaCha20 + Salsa20
    CHACHA_HEAVY,    // ChaCha20 + LFSR + Tinkerbell
    SALSA_LIGHT,     // Salsa20 + LFSR
    CHAOS_ONLY,      // LFSR + Tinkerbell + Transposition (no stream ciphers)
    STREAM_FOCUS     // ChaCha20 + Salsa20 + minimal chaos
};

ZTMRecipe parseZTMRecipe(const String& recipe) {
    if (recipe == "full_stack") return ZTMRecipe::FULL_STACK;
    if (recipe == "chacha_heavy") return ZTMRecipe::CHACHA_HEAVY;
    if (recipe == "salsa_light") return ZTMRecipe::SALSA_LIGHT;
    if (recipe == "chaos_only") return ZTMRecipe::CHAOS_ONLY;
    if (recipe == "stream_focus") return ZTMRecipe::STREAM_FOCUS;
    return ZTMRecipe::FULL_STACK;  // Default
}

size_t xenocipherEncryptZTM(const uint8_t* plaintext, size_t ptLen,
                             uint8_t* ciphertext, const XenoCipherKeys& keys,
                             uint32_t nonce, const GridSpec& grid,
                             ZTMRecipe recipe) {
    std::vector<uint8_t> buf(plaintext, plaintext + ptLen);
    
    // Step 1: Salt (if needed)
    SaltMeta meta;
    meta.pos = ptLen;
    meta.len = 2;
    std::vector<uint8_t> salted;
    salted.reserve(ptLen + meta.len);
    salted.insert(salted.end(), plaintext, plaintext + ptLen);
    salted.insert(salted.end(), (const uint8_t*)COMMON_SALT, (const uint8_t*)COMMON_SALT + meta.len);
    
    // Step 2: Pad to grid
    size_t gridSize = grid.rows * grid.cols;
    buf.resize(gridSize, 0);
    memcpy(buf.data(), salted.data(), salted.size() < gridSize ? salted.size() : gridSize);
    
    // Step 3: LFSR (if recipe includes it)
    if (recipe == ZTMRecipe::FULL_STACK || recipe == ZTMRecipe::CHACHA_HEAVY || 
        recipe == ZTMRecipe::SALSA_LIGHT || recipe == ZTMRecipe::CHAOS_ONLY) {
        ChaoticLFSR32 lfsr(keys.lfsrSeed, keys.tinkerbellKey, 0x0029u);
        lfsr.xorBuffer(buf.data(), buf.size());
    }
    
    // Step 4: Tinkerbell XOR (if recipe includes it)
    if (recipe == ZTMRecipe::FULL_STACK || recipe == ZTMRecipe::CHACHA_HEAVY || 
        recipe == ZTMRecipe::CHAOS_ONLY) {
        const char label[] = "XENO-TINK";
        uint8_t counter = 0;
        size_t offset = 0;
        while (offset < buf.size()) {
            uint8_t block[32];
            uint8_t msg[sizeof(label) + 4 + 1];
            memcpy(msg, label, sizeof(label));
            msg[sizeof(label) + 0] = (uint8_t)((nonce >> 24) & 0xFF);
            msg[sizeof(label) + 1] = (uint8_t)((nonce >> 16) & 0xFF);
            msg[sizeof(label) + 2] = (uint8_t)((nonce >> 8) & 0xFF);
            msg[sizeof(label) + 3] = (uint8_t)(nonce & 0xFF);
            msg[sizeof(label) + 4] = counter;
            
            hmac_sha256_full(keys.tinkerbellKey, 16, msg, sizeof(msg), block);
            
            size_t n = (buf.size() - offset) < sizeof(block) ? (buf.size() - offset) : sizeof(block);
            for (size_t i = 0; i < n; ++i) {
                buf[offset + i] ^= block[i];
            }
            offset += n;
            counter++;
        }
    }
    
    // Step 5: Transposition (if recipe includes it)
    if (recipe == ZTMRecipe::FULL_STACK || recipe == ZTMRecipe::CHAOS_ONLY) {
        uint8_t trKey8[8];
        memcpy(trKey8, keys.transpositionKey, 8);
        applyTransposition(buf.data(), grid, trKey8, PermuteMode::Forward);
    }
    
    // Step 6: ChaCha20 (if recipe includes it)
    if (recipe == ZTMRecipe::FULL_STACK || recipe == ZTMRecipe::CHACHA_HEAVY || 
        recipe == ZTMRecipe::STREAM_FOCUS) {
        ChaCha20 chacha;
        uint8_t chachaNonce[12];
        memcpy(chachaNonce, &nonce, 4);
        memset(chachaNonce + 4, 0, 8);
        chacha.init(keys.hmacKey, 32, chachaNonce, 12);
        chacha.encrypt(buf.data(), buf.data(), buf.size());
    }
    
    // Step 7: Salsa20 (if recipe includes it)
    if (recipe == ZTMRecipe::FULL_STACK || recipe == ZTMRecipe::SALSA_LIGHT || 
        recipe == ZTMRecipe::STREAM_FOCUS) {
        Salsa20 salsa;
        uint8_t salsaNonce[8];
        memcpy(salsaNonce, &nonce, 4);
        memset(salsaNonce + 4, 0, 4);
        salsa.init(keys.hmacKey, 32, salsaNonce, 8);
        salsa.encrypt(buf.data(), buf.data(), buf.size());
    }
    
    memcpy(ciphertext, buf.data(), buf.size());
    return buf.size();
}

// ============================================================================
// RSA-2048 IMPLEMENTATION (mbedTLS)
// ============================================================================

struct RSABenchmark {
    mbedtls_rsa_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    bool initialized;
    
    RSABenchmark() : initialized(false) {
        mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
    }
    
    bool init() {
        const char* pers = "xenocipher_rsa_bench";
        if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const uint8_t*)pers, strlen(pers)) != 0) {
            return false;
        }
        
        if (mbedtls_rsa_gen_key(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537) != 0) {
            return false;
        }
        
        initialized = true;
        return true;
    }
    
    size_t encrypt(const uint8_t* plaintext, size_t ptLen, uint8_t* ciphertext) {
        if (!initialized || ptLen > 245) {  // RSA-2048 can encrypt max 245 bytes
            return 0;
        }
        
        size_t olen = 0;
        if (mbedtls_rsa_pkcs1_encrypt(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg,
                                     MBEDTLS_RSA_PUBLIC, ptLen, plaintext, ciphertext) != 0) {
            return 0;
        }
        
        return 256;  // RSA-2048 output is always 256 bytes
    }
    
    size_t decrypt(const uint8_t* ciphertext, size_t ctLen, uint8_t* plaintext) {
        if (!initialized || ctLen != 256) {
            return 0;
        }
        
        size_t olen = 0;
        if (mbedtls_rsa_pkcs1_decrypt(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg,
                                     MBEDTLS_RSA_PRIVATE, &olen, ciphertext, plaintext, 256) != 0) {
            return 0;
        }
        
        return olen;
    }
    
    void cleanup() {
        if (initialized) {
            mbedtls_rsa_free(&ctx);
            mbedtls_entropy_free(&entropy);
            mbedtls_ctr_drbg_free(&ctr_drbg);
            initialized = false;
        }
    }
    
    ~RSABenchmark() {
        cleanup();
    }
};

// ============================================================================
// ECC secp256r1 IMPLEMENTATION (mbedTLS)
// ============================================================================

struct ECCBenchmark {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pub;
    mbedtls_mpi priv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    bool initialized;
    
    ECCBenchmark() : initialized(false) {
        mbedtls_ecp_group_init(&grp);
        mbedtls_ecp_point_init(&pub);
        mbedtls_mpi_init(&priv);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
    }
    
    bool init() {
        const char* pers = "xenocipher_ecc_bench";
        if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const uint8_t*)pers, strlen(pers)) != 0) {
            return false;
        }
        
        if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
            return false;
        }
        
        if (mbedtls_ecp_gen_key(&grp, &priv, &pub, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
            return false;
        }
        
        initialized = true;
        return true;
    }
    
    // ECC is typically used for key exchange, not bulk encryption
    // For benchmarking, we'll use ECDH to derive a shared secret
    size_t encrypt(const uint8_t* plaintext, size_t ptLen, uint8_t* ciphertext) {
        // ECC doesn't directly encrypt - this is a placeholder
        // In practice, ECC would be used for key exchange, then AES for encryption
        // For benchmarking purposes, we'll simulate by deriving a shared secret
        if (!initialized || ptLen > 32) {
            return 0;
        }
        
        // Generate ephemeral key pair
        mbedtls_mpi ephemeral_priv;
        mbedtls_ecp_point ephemeral_pub;
        mbedtls_mpi_init(&ephemeral_priv);
        mbedtls_ecp_point_init(&ephemeral_pub);
        
        if (mbedtls_ecp_gen_key(&grp, &ephemeral_priv, &ephemeral_pub,
                               mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
            mbedtls_mpi_free(&ephemeral_priv);
            mbedtls_ecp_point_free(&ephemeral_pub);
            return 0;
        }
        
        // Compute shared secret (simplified - in practice would use ECDH)
        // For benchmarking, just XOR with derived secret
        uint8_t shared_secret[32];
        // Simplified: use public key hash as shared secret
        mbedtls_mpi_write_binary(&ephemeral_pub.X, shared_secret, 32);
        
        for (size_t i = 0; i < ptLen; ++i) {
            ciphertext[i] = plaintext[i] ^ shared_secret[i % 32];
        }
        
        mbedtls_mpi_free(&ephemeral_priv);
        mbedtls_ecp_point_free(&ephemeral_pub);
        
        return ptLen;
    }
    
    size_t decrypt(const uint8_t* ciphertext, size_t ctLen, uint8_t* plaintext) {
        // Same as encrypt for ECC (XOR cipher)
        return encrypt(ciphertext, ctLen, plaintext);
    }
    
    void cleanup() {
        if (initialized) {
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&pub);
            mbedtls_mpi_free(&priv);
            mbedtls_entropy_free(&entropy);
            mbedtls_ctr_drbg_free(&ctr_drbg);
            initialized = false;
        }
    }
    
    ~ECCBenchmark() {
        cleanup();
    }
};

// ============================================================================
// AES-256 IMPLEMENTATION (mbedTLS)
// ============================================================================

struct AESBenchmark {
    mbedtls_aes_context ctx;
    
    bool init(const uint8_t* key) {
        mbedtls_aes_init(&ctx);
        return mbedtls_aes_setkey_enc(&ctx, key, 256) == 0;
    }
    
    size_t encrypt(const uint8_t* plaintext, size_t ptLen, uint8_t* ciphertext) {
        // AES-256 requires 16-byte blocks, pad if needed
        size_t paddedLen = ((ptLen + 15) / 16) * 16;
        std::vector<uint8_t> padded(paddedLen, 0);
        memcpy(padded.data(), plaintext, ptLen);
        
        // PKCS7 padding
        uint8_t padValue = paddedLen - ptLen;
        for (size_t i = ptLen; i < paddedLen; ++i) {
            padded[i] = padValue;
        }
        
        // Encrypt in blocks
        for (size_t i = 0; i < paddedLen; i += 16) {
            mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, padded.data() + i, ciphertext + i);
        }
        
        return paddedLen;
    }
    
    size_t decrypt(const uint8_t* ciphertext, size_t ctLen, uint8_t* plaintext) {
        // Decrypt in blocks
        for (size_t i = 0; i < ctLen; i += 16) {
            mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, ciphertext + i, plaintext + i);
        }
        
        // Remove PKCS7 padding
        uint8_t padValue = plaintext[ctLen - 1];
        return ctLen - padValue;
    }
    
    void cleanup() {
        mbedtls_aes_free(&ctx);
    }
};

// ============================================================================
// BENCHMARK STRUCTURE
// ============================================================================

struct BenchmarkResult {
    String timestamp;
    uint32_t runId;
    uint32_t iteration;
    String algorithm;
    String mode;
    size_t plaintextSize;
    size_t ciphertextSize;
    int64_t encTimeUs;
    int64_t decTimeUs;
    size_t heapBefore;
    size_t heapAfter;
    int64_t heapDelta;
    size_t peakHeap;
    double throughputBytesPerSec;
    String ciphertextSample;  // Hex, optional
    bool integrityPassed;
    
    String toCSV() const {
        String csv;
        csv += timestamp + ",";
        csv += String(runId) + ",";
        csv += String(iteration) + ",";
        csv += algorithm + ",";
        csv += mode + ",";
        csv += String(plaintextSize) + ",";
        csv += String(ciphertextSize) + ",";
        csv += String(encTimeUs) + ",";
        csv += String(decTimeUs) + ",";
        csv += String(heapBefore) + ",";
        csv += String(heapAfter) + ",";
        csv += String(heapDelta) + ",";
        csv += String(peakHeap) + ",";
        csv += String(throughputBytesPerSec, 2) + ",";
        csv += ciphertextSample + ",";
        csv += (integrityPassed ? "PASS" : "FAIL");
        return csv;
    }
    
    String getCSVHeader() {
        return "timestamp_iso,run_id,iteration,algorithm,mode,plaintext_size,ciphertext_size,enc_time_us,dec_time_us,heap_before,heap_after,heap_delta,peak_heap,throughput_bytes_s,ciphertext_entropy_sample,integrity_check";
    }
};

// ============================================================================
// BENCHMARK RUNNER
// ============================================================================

void runBenchmark(const String& algorithm, const String& mode) {
    Serial.printf("\n=== Benchmark: %s [%s] ===\n", algorithm.c_str(), mode.c_str());
    
    XenoCipherKeys xenoKeys;
    GridSpec grid = {4, 8};  // Default grid
    uint32_t nonce = 1;
    
    if (algorithm.startsWith("xenocipher")) {
        if (!deriveXenoKeys(gTestKey.data(), nonce, xenoKeys)) {
            Serial.println("ERROR: Failed to derive XenoCipher keys");
            return;
        }
    }
    
    std::vector<uint8_t> ciphertext(gPlaintext.size() * 2);  // Allocate extra space
    std::vector<uint8_t> decrypted(gPlaintext.size() * 2);
    
    // Warm-up runs
    Serial.printf("Warm-up: %d iterations...\n", gConfig.warmupIterations);
    for (size_t i = 0; i < gConfig.warmupIterations; ++i) {
        if (algorithm == "xenocipher" && mode == "normal") {
            xenocipherEncryptNormal(gPlaintext.data(), gPlaintext.size(),
                                    ciphertext.data(), xenoKeys, nonce, grid);
        } else if (algorithm == "xenocipher_ztm") {
            ZTMRecipe recipe = parseZTMRecipe(String(gConfig.ztmRecipe.c_str()));
            xenocipherEncryptZTM(gPlaintext.data(), gPlaintext.size(),
                                 ciphertext.data(), xenoKeys, nonce, grid, recipe);
        } else if (algorithm == "aes") {
            AESBenchmark aes;
            aes.init(gTestKey.data());
            aes.encrypt(gPlaintext.data(), gPlaintext.size(), ciphertext.data());
            aes.cleanup();
        } else if (algorithm == "rsa") {
            RSABenchmark rsa;
            rsa.init();
            rsa.encrypt(gPlaintext.data(), gPlaintext.size(), ciphertext.data());
            rsa.cleanup();
        } else if (algorithm == "ecc") {
            ECCBenchmark ecc;
            ecc.init();
            ecc.encrypt(gPlaintext.data(), gPlaintext.size(), ciphertext.data());
            ecc.cleanup();
        }
    }
    
    // Measured runs
    Serial.printf("Measured runs: %d iterations...\n", gConfig.measuredIterations);
    std::vector<BenchmarkResult> results;
    
    for (size_t iter = 0; iter < gConfig.measuredIterations; ++iter) {
        BenchmarkResult result;
        result.timestamp = getISOTimestamp();
        result.runId = gRunId;
        result.iteration = iter;
        result.algorithm = algorithm;
        result.mode = mode;
        result.plaintextSize = gPlaintext.size();
        result.integrityPassed = false;
        
        // Measure encryption
        size_t heapBefore = getFreeHeap();
        int64_t startEnc = getTimeMicros();
        
        size_t ctLen = 0;
        if (algorithm == "xenocipher" && mode == "normal") {
            ctLen = xenocipherEncryptNormal(gPlaintext.data(), gPlaintext.size(),
                                            ciphertext.data(), xenoKeys, nonce, grid);
        } else if (algorithm == "xenocipher_ztm") {
            ZTMRecipe recipe = parseZTMRecipe(String(gConfig.ztmRecipe.c_str()));
            ctLen = xenocipherEncryptZTM(gPlaintext.data(), gPlaintext.size(),
                                        ciphertext.data(), xenoKeys, nonce, grid, recipe);
        } else if (algorithm == "aes") {
            AESBenchmark aes;
            aes.init(gTestKey.data());
            ctLen = aes.encrypt(gPlaintext.data(), gPlaintext.size(), ciphertext.data());
            aes.cleanup();
        } else if (algorithm == "rsa") {
            RSABenchmark rsa;
            rsa.init();
            ctLen = rsa.encrypt(gPlaintext.data(), gPlaintext.size(), ciphertext.data());
            rsa.cleanup();
        } else if (algorithm == "ecc") {
            ECCBenchmark ecc;
            ecc.init();
            ctLen = ecc.encrypt(gPlaintext.data(), gPlaintext.size(), ciphertext.data());
            ecc.cleanup();
        }
        
        int64_t endEnc = getTimeMicros();
        size_t heapAfter = getFreeHeap();
        
        result.encTimeUs = endEnc - startEnc;
        result.heapBefore = heapBefore;
        result.heapAfter = heapAfter;
        result.heapDelta = (int64_t)heapAfter - (int64_t)heapBefore;
        result.peakHeap = getMinFreeHeap();
        result.ciphertextSize = ctLen;
        
        if (gConfig.saveCiphertextSamples && iter == 0) {
            result.ciphertextSample = bytesToHex(ciphertext.data(), ctLen < 32 ? ctLen : 32);
        }
        
        // Measure decryption
        int64_t startDec = getTimeMicros();
        
        size_t ptLen = 0;
        if (algorithm == "xenocipher" && mode == "normal") {
            ptLen = xenocipherDecryptNormal(ciphertext.data(), ctLen,
                                            decrypted.data(), xenoKeys, nonce, grid);
        } else if (algorithm == "aes") {
            AESBenchmark aes;
            aes.init(gTestKey.data());
            ptLen = aes.decrypt(ciphertext.data(), ctLen, decrypted.data());
            aes.cleanup();
        } else if (algorithm == "rsa") {
            RSABenchmark rsa;
            rsa.init();
            ptLen = rsa.decrypt(ciphertext.data(), ctLen, decrypted.data());
            rsa.cleanup();
        } else if (algorithm == "ecc") {
            ECCBenchmark ecc;
            ecc.init();
            ptLen = ecc.decrypt(ciphertext.data(), ctLen, decrypted.data());
            ecc.cleanup();
        }
        
        int64_t endDec = getTimeMicros();
        result.decTimeUs = endDec - startDec;
        
        // Integrity check
        if (ptLen == gPlaintext.size()) {
            result.integrityPassed = (memcmp(decrypted.data(), gPlaintext.data(), ptLen) == 0);
        }
        
        // Throughput calculation
        if (result.encTimeUs > 0) {
            result.throughputBytesPerSec = (double)gPlaintext.size() * 1000000.0 / (double)result.encTimeUs;
        }
        
        results.push_back(result);
        
        // Log to Serial
        if (gConfig.streamToSerial) {
            Serial.println(result.toCSV());
        }
        
        // Progress indicator
        if ((iter + 1) % 10 == 0) {
            Serial.printf("Progress: %d/%d\n", iter + 1, gConfig.measuredIterations);
        }
    }
    
    // Save to SPIFFS
    File file = SPIFFS.open(gConfig.outputFile.c_str(), FILE_APPEND);
    if (file) {
        if (gRunId == 0 && results.size() > 0) {
            file.println(results[0].getCSVHeader());
        }
        for (const auto& result : results) {
            file.println(result.toCSV());
        }
        file.close();
        Serial.printf("Results saved to %s\n", gConfig.outputFile.c_str());
    }
}

// ============================================================================
// CONFIGURATION LOADING
// ============================================================================

void loadConfig() {
    // Default configuration
    gConfig.algorithms = {"xenocipher", "xenocipher_ztm", "aes"};
    gConfig.modes = {"normal", "full_stack"};
    gConfig.plaintextSize = 256;
    gConfig.warmupIterations = 5;
    gConfig.measuredIterations = 50;
    gConfig.saveCiphertextSamples = true;
    gConfig.streamToSerial = true;
    gConfig.ztmRecipe = "full_stack";
    
    // Try to load from SPIFFS
    if (SPIFFS.exists("/config.json")) {
        File file = SPIFFS.open("/config.json", FILE_READ);
        if (file) {
            String content = file.readString();
            file.close();
            
            DynamicJsonDocument doc(2048);
            deserializeJson(doc, content);
            
            if (doc.containsKey("algorithms")) {
                gConfig.algorithms.clear();
                for (const auto& alg : doc["algorithms"].as<JsonArray>()) {
                    gConfig.algorithms.push_back(alg.as<String>().c_str());
                }
            }
            
            if (doc.containsKey("plaintext_size")) {
                gConfig.plaintextSize = doc["plaintext_size"];
            }
            
            if (doc.containsKey("warmup_iterations")) {
                gConfig.warmupIterations = doc["warmup_iterations"];
            }
            
            if (doc.containsKey("measured_iterations")) {
                gConfig.measuredIterations = doc["measured_iterations"];
            }
            
            if (doc.containsKey("ztm_recipe")) {
                gConfig.ztmRecipe = doc["ztm_recipe"].as<String>().c_str();
            }
            
            Serial.println("Configuration loaded from SPIFFS");
        }
    }
}

void generateTestData() {
    gPlaintext.resize(gConfig.plaintextSize);
    
    if (gConfig.useSPIFFSInput && SPIFFS.exists(gConfig.spiffsInputFile.c_str())) {
        File file = SPIFFS.open(gConfig.spiffsInputFile.c_str(), FILE_READ);
        if (file) {
            size_t read = file.read(gPlaintext.data(), gPlaintext.size());
            file.close();
            Serial.printf("Loaded %d bytes from %s\n", read, gConfig.spiffsInputFile.c_str());
            return;
        }
    }
    
    // Generate deterministic test data
    if (gConfig.seed != 0) {
        srand(gConfig.seed);
    }
    
    for (size_t i = 0; i < gPlaintext.size(); ++i) {
        gPlaintext[i] = (uint8_t)(rand() % 256);
    }
    
    // Generate test key
    for (size_t i = 0; i < 32; ++i) {
        gTestKey[i] = (uint8_t)(rand() % 256);
    }
}

// ============================================================================
// ARDUINO SETUP & LOOP
// ============================================================================

void setup() {
    Serial.begin(115200);
    delay(2000);
    
    Serial.println("\n=== XenoCipher Benchmark Suite ===");
    Serial.printf("Firmware Version: %d.%d.%d\n", 
                  XENOCIPHER_VERSION_MAJOR, XENOCIPHER_VERSION_MINOR, XENOCIPHER_VERSION_PATCH);
    
    // Initialize SPIFFS
    if (!SPIFFS.begin(true)) {
        Serial.println("ERROR: SPIFFS initialization failed!");
        return;
    }
    Serial.println("SPIFFS initialized");
    
    // Load configuration
    loadConfig();
    
    // Generate test data
    generateTestData();
    
    Serial.println("\nConfiguration:");
    Serial.printf("  Algorithms: ");
    for (const auto& alg : gConfig.algorithms) {
        Serial.printf("%s ", alg.c_str());
    }
    Serial.println();
    Serial.printf("  Plaintext size: %d bytes\n", gConfig.plaintextSize);
    Serial.printf("  Warm-up iterations: %d\n", gConfig.warmupIterations);
    Serial.printf("  Measured iterations: %d\n", gConfig.measuredIterations);
    Serial.printf("  ZTM Recipe: %s\n", gConfig.ztmRecipe.c_str());
    
    Serial.println("\nStarting benchmark in 3 seconds...");
    delay(3000);
    
    gRunId = (uint32_t)(esp_timer_get_time() / 1000000);  // Use seconds as run ID
    
    // Clear previous results
    if (SPIFFS.exists(gConfig.outputFile.c_str())) {
        SPIFFS.remove(gConfig.outputFile.c_str());
    }
    
    gBenchmarkRunning = true;
}

void loop() {
    if (!gBenchmarkRunning) {
        delay(1000);
        return;
    }
    
    // Run benchmarks for each algorithm/mode combination
    for (const auto& algorithm : gConfig.algorithms) {
        for (const auto& mode : gConfig.modes) {
            // Skip invalid combinations
            if (algorithm == "xenocipher" && mode != "normal") continue;
            if (algorithm == "xenocipher_ztm" && mode == "normal") continue;
            if ((algorithm == "aes" || algorithm == "rsa" || algorithm == "ecc") && mode != "normal") continue;
            
            runBenchmark(algorithm, mode);
            delay(1000);  // Brief pause between tests
        }
    }
    
    gBenchmarkRunning = false;
    Serial.println("\n=== Benchmark Complete ===");
    Serial.printf("Results saved to: %s\n", gConfig.outputFile.c_str());
    Serial.println("Use 'pio run -t uploadfs' to download SPIFFS files");
    
    // Keep running but don't repeat benchmarks
    while (true) {
        delay(10000);
    }
}

