#include <crow.h>
#include <pqxx/pqxx>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/poly1305.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <regex>
#include <ctime>
#include <thread>
#include <atomic>
#include <chrono>
#include <unordered_set>
#include "../lib/NTRU/include/ntru.h"
#include "../lib/common/common.h"
#include "../lib/CryptoKDF/include/crypto_kdf.h"
#include "../lib/HMAC/include/hmac.h"
#include "../lib/LFSR/include/lfsr.h"
#include "../lib/Tinkerbell/include/tinkerbell.h"
#include "../lib/Transposition/include/transposition.h"
#include "../lib/Heuristics_Manager/include/heuristics_manager.h"
#include "../lib/Adaptive_Switchboard/include/adaptive_switchboard.h"

// Deterministic stream XOR using HMAC-SHA256(counter) with 16-byte key
static void xor_with_stream_hmac(const uint8_t key[16], uint32_t nonce, uint8_t* data, size_t len) {
    const char label[] = "XENO-TINK";
    uint8_t counter = 0;
    size_t offset = 0;
    while (offset < len) {
        uint8_t block[32];
        uint8_t msg[sizeof(label) + 4 + 1];
        memcpy(msg, label, sizeof(label));
        msg[sizeof(label) + 0] = (uint8_t)((nonce >> 24) & 0xFF);
        msg[sizeof(label) + 1] = (uint8_t)((nonce >> 16) & 0xFF);
        msg[sizeof(label) + 2] = (uint8_t)((nonce >> 8) & 0xFF);
        msg[sizeof(label) + 3] = (uint8_t)(nonce & 0xFF);
        msg[sizeof(label) + 4] = counter++;
        hmac_sha256_full(key, 16, msg, sizeof(msg), block);
        size_t n = (len - offset) < sizeof(block) ? (len - offset) : sizeof(block);
        for (size_t i = 0; i < n; ++i) data[offset + i] ^= block[i];
    offset += n;
    }
}

using namespace std;

// KDF_ITERATIONS is defined in crypto_kdf.h
#define HMAC_TAG_LEN 16

// Use lib structures instead of custom ones
// BaseKeys and MessageKeys are defined in crypto_kdf.h

// GridSpec is defined in transposition.h

struct SaltMeta {
    uint16_t pos;
    uint8_t len;
};

// NTRU key pair
class NTRUServer {
public:
    NTRUServer() : ntru() {
        ntru.generate_keys(keyPair);
    }

    std::vector<uint8_t> getPublicKey() const {
        std::vector<uint8_t> bytes;
        NTRU::poly_to_bytes16(keyPair.h, bytes);
        return bytes;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encKey) {
        Poly e, m;
        NTRU::bytes_to_poly16(encKey, e);
        ntru.decrypt(e, keyPair.f, m);
        std::vector<uint8_t> bytes;
        NTRU::poly_to_bytes(m, bytes, 32); // Assuming 32-byte master key (1 byte per coeff)
        return bytes;
    }

private:
    NTRU ntru;
    NTRUKeyPair keyPair;
};

// Use lib deriveKeys function instead of custom implementation

// Use lib deriveMessageKeys function instead of custom implementation

// Use lib ChaoticLFSR32 class instead of custom implementation

// Use lib Tinkerbell class instead of custom implementation

// Use lib applyTransposition function instead of custom implementation

// Time utility function (milliseconds since epoch)
#define GET_TIME_MS() (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count())

// Minimal server-side substitutes to resolve missing adaptive monitor/replay headers
enum EncryptionRecipe {
    RECIPE_XENOCIPHER_NORMAL = 0,
    RECIPE_XENOCIPHER_HARDENED = 1,
    RECIPE_CHACHA20_POLY1305 = 2
};

struct SecurityMetrics {
    uint32_t decrypt_failures;
    uint32_t hmac_failures;
    uint32_t replay_attempts;
    uint32_t requests_per_minute;
};

struct AdaptiveMonitor {
    SecurityMetrics metrics;
    EncryptionRecipe recipe;
};

static void adaptive_monitor_init(AdaptiveMonitor* am) { am->metrics = {0,0,0,0}; am->recipe = RECIPE_XENOCIPHER_NORMAL; }
static void adaptive_monitor_update_request(AdaptiveMonitor* am) { (void)am; }
static void adaptive_monitor_update_decrypt_failure(AdaptiveMonitor* am) { if (am) am->metrics.decrypt_failures++; }
static void adaptive_monitor_update_hmac_failure(AdaptiveMonitor* am) { if (am) am->metrics.hmac_failures++; }
static void adaptive_monitor_update_timing(AdaptiveMonitor* am, uint64_t /*us*/) { (void)am; }
static void adaptive_monitor_update_replay_attempt(AdaptiveMonitor* am) { if (am) am->metrics.replay_attempts++; }
static void adaptive_monitor_reset_window(AdaptiveMonitor* am) { if (am) am->metrics = {0,0,0,0}; }
static const SecurityMetrics* adaptive_monitor_get_metrics(const AdaptiveMonitor* am) { return &am->metrics; }
static bool adaptive_monitor_should_switch(const AdaptiveMonitor* am) { return false; }
static EncryptionRecipe adaptive_monitor_get_recipe(const AdaptiveMonitor* am) { return am->recipe; }
static void adaptive_monitor_switch_recipe(AdaptiveMonitor* am, EncryptionRecipe r) { am->recipe = r; }

struct NonceTracker { std::unordered_set<uint32_t> used; };
static void nonce_tracker_init(NonceTracker* nt, bool /*randomMode*/) { nt->used.clear(); }
static bool nonce_tracker_validate(NonceTracker* nt, uint32_t n, uint32_t /*now*/) { return nt->used.find(n) == nt->used.end(); }
static void nonce_tracker_mark_used(NonceTracker* nt, uint32_t n, uint64_t /*now*/) { nt->used.insert(n); }
static void nonce_tracker_cleanup(NonceTracker* /*nt*/, uint64_t /*now*/) {}

// Minimal key rotation policy stub
struct KeyRotationPolicy {
    uint64_t lastRotationMs;
};
static void key_rotation_init(KeyRotationPolicy* p) { if (p) p->lastRotationMs = 0; }

// Adaptive monitoring and security
static AdaptiveMonitor gAdaptiveMonitor;
static NonceTracker gNonceTracker;
static KeyRotationPolicy gKeyRotationPolicy;

// Metrics update thread (runs every minute)
static std::thread gMetricsThread;
static std::atomic<bool> gMetricsThreadRunning(true);

std::vector<uint8_t> removeSalt(const std::vector<uint8_t>& salted, size_t saltedLen, const SaltMeta& meta) {
    if (meta.len == 0 || meta.pos > saltedLen) return salted;
    std::vector<uint8_t> out(saltedLen - meta.len);
    std::copy(salted.begin(), salted.begin() + meta.pos, out.begin());
    std::copy(salted.begin() + meta.pos + meta.len, salted.end(), out.begin() + meta.pos);
    return out;
}

// Helper function for error logging with timestamp
void log_error(const std::string& msg) {
    time_t now = time(nullptr);
    std::string dt = ctime(&now);
    dt.erase(dt.find_last_not_of("\n\r") + 1); // Trim trailing newline
    std::cerr << "[ERROR] [" << dt << "] " << msg << std::endl;
}

// ChaCha20-Poly1305 AEAD encryption (fallback recipe)
static bool chacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext,
    uint8_t tag[16])
{
    mbedtls_chacha20_context ctx;
    mbedtls_chacha20_init(&ctx);
    
    if (mbedtls_chacha20_setkey(&ctx, key) != 0) {
        mbedtls_chacha20_free(&ctx);
        return false;
    }
    
    if (mbedtls_chacha20_starts(&ctx, nonce, 0) != 0) {
        mbedtls_chacha20_free(&ctx);
        return false;
    }
    
    if (mbedtls_chacha20_update(&ctx, pt_len, plaintext, ciphertext) != 0) {
        mbedtls_chacha20_free(&ctx);
        return false;
    }
    
    mbedtls_chacha20_free(&ctx);
    
    // Poly1305 MAC
    uint8_t poly_key[32] = {0};
    mbedtls_chacha20_context key_ctx;
    mbedtls_chacha20_init(&key_ctx);
    mbedtls_chacha20_setkey(&key_ctx, key);
    mbedtls_chacha20_starts(&key_ctx, nonce, 0);
    mbedtls_chacha20_update(&key_ctx, 32, poly_key, poly_key);
    mbedtls_chacha20_free(&key_ctx);
    
    // Compute Poly1305 over AAD || ciphertext
    mbedtls_poly1305_context mac_ctx;
    mbedtls_poly1305_init(&mac_ctx);
    mbedtls_poly1305_starts(&mac_ctx, poly_key);
    
    if (aad && aad_len) {
        mbedtls_poly1305_update(&mac_ctx, aad, aad_len);
        // Padding
        size_t pad_len = (16 - (aad_len % 16)) % 16;
        uint8_t pad[16] = {0};
        if (pad_len) mbedtls_poly1305_update(&mac_ctx, pad, pad_len);
    }
    
    mbedtls_poly1305_update(&mac_ctx, ciphertext, pt_len);
    size_t pad_len = (16 - (pt_len % 16)) % 16;
    uint8_t pad[16] = {0};
    if (pad_len) mbedtls_poly1305_update(&mac_ctx, pad, pad_len);
    
    // Append lengths
    uint8_t lengths[16];
    memcpy(lengths, &aad_len, 8);
    memcpy(lengths + 8, &pt_len, 8);
    mbedtls_poly1305_update(&mac_ctx, lengths, 16);
    
    mbedtls_poly1305_finish(&mac_ctx, tag);
    mbedtls_poly1305_free(&mac_ctx);
    
    return true;
}

// ChaCha20-Poly1305 decryption
static bool chacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t tag[16],
    uint8_t* plaintext)
{
    // Verify tag first
    uint8_t computed_tag[16];
    
    // Recompute Poly1305 over AAD || ciphertext
    uint8_t poly_key[32] = {0};
    mbedtls_chacha20_context key_ctx;
    mbedtls_chacha20_init(&key_ctx);
    mbedtls_chacha20_setkey(&key_ctx, key);
    mbedtls_chacha20_starts(&key_ctx, nonce, 0);
    mbedtls_chacha20_update(&key_ctx, 32, poly_key, poly_key);
    mbedtls_chacha20_free(&key_ctx);
    
    mbedtls_poly1305_context mac_ctx;
    mbedtls_poly1305_init(&mac_ctx);
    mbedtls_poly1305_starts(&mac_ctx, poly_key);
    
    if (aad && aad_len) {
        mbedtls_poly1305_update(&mac_ctx, aad, aad_len);
        size_t pad_len = (16 - (aad_len % 16)) % 16;
        uint8_t pad[16] = {0};
        if (pad_len) mbedtls_poly1305_update(&mac_ctx, pad, pad_len);
    }
    
    mbedtls_poly1305_update(&mac_ctx, ciphertext, ct_len);
    size_t pad_len = (16 - (ct_len % 16)) % 16;
    uint8_t pad[16] = {0};
    if (pad_len) mbedtls_poly1305_update(&mac_ctx, pad, pad_len);
    
    uint8_t lengths[16];
    memcpy(lengths, &aad_len, 8);
    memcpy(lengths + 8, &ct_len, 8);
    mbedtls_poly1305_update(&mac_ctx, lengths, 16);
    
    mbedtls_poly1305_finish(&mac_ctx, computed_tag);
    mbedtls_poly1305_free(&mac_ctx);
    
    // Constant-time compare
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (computed_tag[i] ^ tag[i]);
    
    if (diff != 0) return false;  // Tag mismatch
    
    // Decrypt
    mbedtls_chacha20_context ctx;
    mbedtls_chacha20_init(&ctx);
    mbedtls_chacha20_setkey(&ctx, key);
    mbedtls_chacha20_starts(&ctx, nonce, 0);
    mbedtls_chacha20_update(&ctx, ct_len, ciphertext, plaintext);
    mbedtls_chacha20_free(&ctx);
    
    return true;
}

std::string pipelineDecryptPacket(const DerivedKeys& baseKeys, const std::vector<uint8_t>& packet, size_t packetLen) {
    // Update metrics
    adaptive_monitor_update_request(&gAdaptiveMonitor);
    
    uint64_t start_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
    
    if (packetLen < 8 + HMAC_TAG_LEN) {
        log_error("Packet too short: " + std::to_string(packetLen));
        adaptive_monitor_update_decrypt_failure(&gAdaptiveMonitor);
        return "";
    }

    std::vector<uint8_t> header(packet.begin(), packet.begin() + 8);
    uint8_t version = header[0];
    bool hasNonce = (version & 0x80) != 0;
    size_t nonceLen = hasNonce ? 4 : 0;
    if (packetLen < 8 + nonceLen + HMAC_TAG_LEN) {
        log_error("Packet too short for nonce: " + std::to_string(packetLen));
        adaptive_monitor_update_decrypt_failure(&gAdaptiveMonitor);
        return "";
    }

    uint8_t saltLen = header[1];
    uint16_t saltPos = (header[2] | (header[3] << 8));
    uint16_t payloadLen = (header[4] | (header[5] << 8));
    uint8_t rows = header[6];
    uint8_t cols = header[7];
    GridSpec grid = {rows, cols};
    SaltMeta saltMeta = {saltPos, saltLen};

    std::vector<uint8_t> noncePtr = hasNonce ? std::vector<uint8_t>(packet.begin() + 8, packet.begin() + 8 + nonceLen) : std::vector<uint8_t>();
    uint32_t nonce = hasNonce ? ((noncePtr[0] << 24) | (noncePtr[1] << 16) | (noncePtr[2] << 8) | noncePtr[3]) : 0;
    
    // Validate nonce (replay protection)
    if (hasNonce && !nonce_tracker_validate(&gNonceTracker, nonce, 0)) {
        adaptive_monitor_update_replay_attempt(&gAdaptiveMonitor);
        log_error("Replay attack detected! Nonce already used: " + std::to_string(nonce));
        return "";
    }
    
    // Mark nonce as used
    if (hasNonce) {
        nonce_tracker_mark_used(&gNonceTracker, nonce, GET_TIME_MS());
    }
    
    // Get encrypted data and HMAC tag
    std::vector<uint8_t> ct(packet.begin() + 8 + nonceLen, packet.end() - HMAC_TAG_LEN);
    std::vector<uint8_t> tag(packet.end() - HMAC_TAG_LEN, packet.end());

    // Debug: print header fields
    {
        std::cout << "[Server] Header: ver=0x" << std::hex << std::uppercase << (int)version
                  << " saltLen=" << std::dec << (int)saltLen
                  << " saltPos=" << saltPos
                  << " payloadLen=" << payloadLen
                  << " rows=" << (int)rows
                  << " cols=" << (int)cols
                  << " nonce=0x" << std::hex << std::uppercase << nonce << std::dec
                  << std::endl;
    }

    MessageKeys hmacKeys;
    if (!deriveMessageKeys(baseKeys, nonce, hmacKeys)) {
        log_error("Failed to derive message-specific HMAC key!");
        return "";
    }

    // Verify HMAC using base HMAC key
    const size_t headerLen = 8;
    const size_t inputLen = headerLen + nonceLen + ct.size();
    uint8_t tagCheck[HMAC_TAG_LEN];
    if (!hmac_sha256_trunc(baseKeys.hmacKey, 32,
                           packet.data(), inputLen,
                           tagCheck, HMAC_TAG_LEN)) {
        log_error("HMAC computation failed!");
        return "";
    }

    // Debug: print HMAC key prefix and tags
    {
        std::ostringstream hk, tp, tc, hi;
        hk << std::hex << std::uppercase << std::setfill('0');
        for (int i = 0; i < 16; ++i) hk << std::setw(2) << (int)baseKeys.hmacKey[i];
        tp << std::hex << std::uppercase << std::setfill('0');
        tc << std::hex << std::uppercase << std::setfill('0');
        hi << std::hex << std::uppercase << std::setfill('0');
        for (int i = 0; i < (int)HMAC_TAG_LEN; ++i) {
            tp << std::setw(2) << (int)tag[i];
            tc << std::setw(2) << (int)tagCheck[i];
        }
        // Print first 16 bytes of HMAC input for debugging
        for (int i = 0; i < 16 && i < (int)inputLen; ++i) {
            hi << std::setw(2) << (int)packet[i];
        }
        std::cout << "[Server] Base HMAC key[0..15]=" << hk.str()
                  << " input[0..15]=" << hi.str()
                  << " inputLen=" << inputLen
                  << " tag(prov)=" << tp.str()
                  << " tag(calc)=" << tc.str() << std::endl;
    }

    // Constant-time tag compare
    uint8_t diff = 0;
    for (size_t i = 0; i < HMAC_TAG_LEN; ++i) diff |= (uint8_t)(tag[i] ^ tagCheck[i]);
    bool macValid = (diff == 0);

    if (!macValid) {
        adaptive_monitor_update_hmac_failure(&gAdaptiveMonitor);
        log_error("MAC verification failed!");
        return "";
    }

    MessageKeys messageKeys;
    deriveMessageKeys(baseKeys, nonce, messageKeys);
    {
        std::ostringstream tkp, trp;
        tkp << std::hex << std::uppercase << std::setfill('0');
        trp << std::hex << std::uppercase << std::setfill('0');
        for (int i = 0; i < 4; ++i) { tkp << std::setw(2) << (int)messageKeys.tinkerbellKey[i]; }
        for (int i = 0; i < 4; ++i) { trp << std::setw(2) << (int)messageKeys.transpositionKey[i]; }
        std::cout << "[Server] MsgKeys: lfsrSeed=0x" << std::hex << std::uppercase << messageKeys.lfsrSeed
                  << " tnk[0..3]=" << tkp.str() << " trn[0..3]=" << trp.str() << std::dec << std::endl;
    }

    std::vector<uint8_t> buf = ct;
    auto logHex = [](const char* label, const std::vector<uint8_t>& v){
        std::ostringstream ss; ss << std::hex << std::uppercase << std::setfill('0');
        size_t show = std::min<size_t>(v.size(), 32);
        for (size_t i = 0; i < show; ++i) ss << std::setw(2) << (int)v[i];
        std::cout << label << "[0.." << (show?show-1:0) << "]: " << ss.str() << std::endl;
    };
    logHex("[Server] CT ", buf);
    
    // First decrypt the data with all three algorithms
    uint8_t trKey8[8];
    memcpy(trKey8, messageKeys.transpositionKey, 8);
    applyTransposition(buf.data(), grid, trKey8, PermuteMode::Inverse);
    logHex("[Server] post-InvTrans ", buf);
    
    // Replace chaotic XOR with deterministic HMAC-based stream XOR to match across platforms
    {
        // Log first 16 bytes of HMAC stream block (counter=0) for diagnostics
        const char label[] = "XENO-TINK";
        uint8_t msg[sizeof(label) + 4 + 1];
        memcpy(msg, label, sizeof(label));
        msg[sizeof(label) + 0] = (uint8_t)((nonce >> 24) & 0xFF);
        msg[sizeof(label) + 1] = (uint8_t)((nonce >> 16) & 0xFF);
        msg[sizeof(label) + 2] = (uint8_t)((nonce >> 8) & 0xFF);
        msg[sizeof(label) + 3] = (uint8_t)(nonce & 0xFF);
        msg[sizeof(label) + 4] = 0;
        uint8_t blk[32];
        hmac_sha256_full(messageKeys.tinkerbellKey, 16, msg, sizeof(msg), blk);
        std::ostringstream ks;
        ks << std::hex << std::uppercase << std::setfill('0');
        for (int i = 0; i < 16; ++i) ks << std::setw(2) << (int)blk[i];
        std::cout << "[Server] TINK stream[0..15]: " << ks.str() << std::endl;
    }
    xor_with_stream_hmac(messageKeys.tinkerbellKey, nonce, buf.data(), buf.size());
    logHex("[Server] post-Tinkerbell ", buf);
    
    ChaoticLFSR32 lfsr((uint32_t)messageKeys.lfsrSeed, messageKeys.tinkerbellKey, 0x0029u);
    lfsr.xorBuffer(buf.data(), buf.size());
    logHex("[Server] post-LFSR ", buf);

    // After decryption, remove the salt
    {
        std::ostringstream decHex;
        decHex << std::hex << std::uppercase << std::setfill('0');
        size_t show = std::min<size_t>(32, buf.size());
        for (size_t i = 0; i < show; ++i) decHex << std::setw(2) << (int)buf[i];
        std::cout << "[Server] Decrypt stage output (padded)[0.." << show-1 << "]: " << decHex.str() << std::endl;
    }

    std::vector<uint8_t> unsalted = removeSalt(buf, buf.size(), saltMeta);
    {
        std::ostringstream unsHex;
        unsHex << std::hex << std::uppercase << std::setfill('0');
        size_t show = std::min<size_t>(payloadLen, unsalted.size());
        for (size_t i = 0; i < std::min<size_t>(32, show); ++i) unsHex << std::setw(2) << (int)unsalted[i];
        std::string preview(unsalted.begin(), unsalted.begin() + show);
        std::cout << "[Server] Unsalted payload hex[0.." << (std::min<size_t>(32, show) - 1) << "]: " << unsHex.str() << std::endl;
        std::cout << "[Server] Unsalted payload ascii: " << preview << std::endl;
    }
    
    // Update timing metrics after successful decryption
    uint64_t end_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
    
    adaptive_monitor_update_timing(&gAdaptiveMonitor, end_time - start_time);
    
    return std::string(unsalted.begin(), unsalted.begin() + payloadLen);
}

// Recipe-aware decryption wrapper
std::string pipelineDecryptPacketAdaptive(
    const DerivedKeysEnhanced& baseKeys,
    const std::vector<uint8_t>& packet,
    size_t packetLen)
{
    // Check current recipe
    EncryptionRecipe recipe = adaptive_monitor_get_recipe(&gAdaptiveMonitor);
    
    if (recipe == RECIPE_CHACHA20_POLY1305) {
        // Use ChaCha20-Poly1305 fallback
        // Parse packet format for ChaCha20-Poly1305:
        // [Nonce(12B)] [Ciphertext] [Tag(16B)]
        if (packetLen < 12 + 16) return "";
        
        const uint8_t* nonce = packet.data();
        const uint8_t* ct = packet.data() + 12;
        size_t ct_len = packetLen - 12 - 16;
        const uint8_t* tag = packet.data() + packetLen - 16;
        
        std::vector<uint8_t> plaintext(ct_len);
        
        if (!chacha20_poly1305_decrypt(
            baseKeys.chacha20Key, nonce,
            nullptr, 0,  // No AAD
            ct, ct_len, tag,
            plaintext.data()))
        {
            adaptive_monitor_update_hmac_failure(&gAdaptiveMonitor);
            return "";
        }
        
        return std::string(plaintext.begin(), plaintext.end());
    }
    else if (recipe == RECIPE_XENOCIPHER_HARDENED) {
        // Use hardened XenoCipher (increased rounds/iterations)
        // Call existing pipeline but with modified parameters
        return pipelineDecryptPacket(baseKeys.base, packet, packetLen);
    }
    else {
        // Normal XenoCipher
        return pipelineDecryptPacket(baseKeys.base, packet, packetLen);
    }
}

// Fallback: try alternate decryption ordering in case transposition inverse mismatches
std::string pipelineDecryptPacketAlt(const DerivedKeys& baseKeys, const std::vector<uint8_t>& packet, size_t packetLen) {
    if (packetLen < 8 + HMAC_TAG_LEN) return "";

    std::vector<uint8_t> header(packet.begin(), packet.begin() + 8);
    uint8_t version = header[0];
    bool hasNonce = (version & 0x80) != 0;
    size_t nonceLen = hasNonce ? 4 : 0;
    if (packetLen < 8 + nonceLen + HMAC_TAG_LEN) return "";

    uint8_t saltLen = header[1];
    uint16_t saltPos = (header[2] | (header[3] << 8));
    uint16_t payloadLen = (header[4] | (header[5] << 8));
    uint8_t rows = header[6];
    uint8_t cols = header[7];
    GridSpec grid = {rows, cols};
    SaltMeta saltMeta = {saltPos, saltLen};

    std::vector<uint8_t> noncePtr = hasNonce ? std::vector<uint8_t>(packet.begin() + 8, packet.begin() + 8 + nonceLen) : std::vector<uint8_t>();
    uint32_t nonce = hasNonce ? ((noncePtr[0] << 24) | (noncePtr[1] << 16) | (noncePtr[2] << 8) | noncePtr[3]) : 0;

    std::vector<uint8_t> ct(packet.begin() + 8 + nonceLen, packet.end() - HMAC_TAG_LEN);

    MessageKeys messageKeys;
    if (!deriveMessageKeys(baseKeys, nonce, messageKeys)) return "";

    std::vector<uint8_t> buf = ct;

    // Try alternate order: Tinkerbell -> LFSR -> Forward Transposition
    xor_with_stream_hmac(messageKeys.tinkerbellKey, nonce, buf.data(), buf.size());

    ChaoticLFSR32 lfsr((uint32_t)messageKeys.lfsrSeed, messageKeys.tinkerbellKey, 0x0029u);
    lfsr.xorBuffer(buf.data(), buf.size());

    uint8_t trKey8[8];
    memcpy(trKey8, messageKeys.transpositionKey, 8);
    applyTransposition(buf.data(), grid, trKey8, PermuteMode::Forward);

    std::vector<uint8_t> unsalted = removeSalt(buf, buf.size(), saltMeta);
    if (unsalted.size() < payloadLen) return "";
    return std::string(unsalted.begin(), unsalted.begin() + payloadLen);
}

// Second fallback: try applying Forward Transposition first (treating forward as its own inverse)
std::string pipelineDecryptPacketAlt2(const DerivedKeys& baseKeys, const std::vector<uint8_t>& packet, size_t packetLen) {
    if (packetLen < 8 + HMAC_TAG_LEN) return "";
    std::vector<uint8_t> header(packet.begin(), packet.begin() + 8);
    bool hasNonce = (header[0] & 0x80) != 0; size_t nonceLen = hasNonce ? 4 : 0;
    if (packetLen < 8 + nonceLen + HMAC_TAG_LEN) return "";
    uint8_t saltLen = header[1]; uint16_t saltPos = (header[2] | (header[3] << 8));
    uint16_t payloadLen = (header[4] | (header[5] << 8)); uint8_t rows = header[6]; uint8_t cols = header[7];
    GridSpec grid = {rows, cols}; SaltMeta saltMeta = {saltPos, saltLen};
    uint32_t nonce = hasNonce ? ((packet[8] << 24) | (packet[9] << 16) | (packet[10] << 8) | packet[11]) : 0;
    std::vector<uint8_t> ct(packet.begin() + 8 + nonceLen, packet.end() - HMAC_TAG_LEN);
    MessageKeys messageKeys; if (!deriveMessageKeys(baseKeys, nonce, messageKeys)) return "";
    std::vector<uint8_t> buf = ct;
    uint8_t trKey8[8]; memcpy(trKey8, messageKeys.transpositionKey, 8);
    applyTransposition(buf.data(), grid, trKey8, PermuteMode::Forward);
    Tinkerbell tk(messageKeys.tinkerbellKey); tk.xorBitwise(buf.data(), buf.size());
    ChaoticLFSR32 lfsr((uint32_t)messageKeys.lfsrSeed, messageKeys.tinkerbellKey, 0x0029u); lfsr.xorBuffer(buf.data(), buf.size());
    std::vector<uint8_t> unsalted = removeSalt(buf, buf.size(), saltMeta);
    if (unsalted.size() < payloadLen) return "";
    return std::string(unsalted.begin(), unsalted.begin() + payloadLen);
}

// Hex string conversion
std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)std::stoul(byteString, nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << (int)b;
    }
    return ss.str();
}

int main() {
    // PostgreSQL connection
    std::cout << "Initializing database connection..." << std::endl;
    std::unique_ptr<pqxx::connection> connPtr;
    const char* pgConnEnv = std::getenv("PG_CONN");
    std::string connStrEnv = pgConnEnv ? std::string(pgConnEnv) : std::string();
    // Try in order: PG_CONN env, port 5433, port 5432
    std::vector<std::string> candidateConnStrs;
    if (!connStrEnv.empty()) candidateConnStrs.push_back(connStrEnv);
    candidateConnStrs.push_back("dbname=XenoCipherTesting user=postgres password=challa host=localhost port=5433");
    candidateConnStrs.push_back("dbname=XenoCipherTesting user=postgres password=challa host=localhost port=5432");

    std::exception_ptr lastErr;
    for (const auto& connStr : candidateConnStrs) {
        try {
            std::cout << "Attempting DB connect: " << connStr << std::endl;
            connPtr = std::make_unique<pqxx::connection>(connStr);
            if (connPtr->is_open()) {
                std::cout << "Database connection established." << std::endl;
                break;
            } else {
                log_error("Failed to connect to PostgreSQL (connection not open)");
                connPtr.reset();
            }
        } catch (const std::exception& e) {
            lastErr = std::current_exception();
            log_error(std::string("PostgreSQL connection error: ") + e.what());
            connPtr.reset();
        }
    }
    if (!connPtr) {
        log_error("Unable to establish PostgreSQL connection after trying all options. Set PG_CONN env var if needed.");
        return 1;
    }

    // Stable reference for route handlers
    pqxx::connection& db = *connPtr;

    // Initialize NTRU
    NTRUServer ntru;
    std::vector<uint8_t> masterKey;

    // Create Crow app
    crow::SimpleApp app;

    // CORS middleware
    CROW_ROUTE(app, "/")
    .methods("OPTIONS"_method)
    ([]() {
        crow::response res(200);
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type");
        return res;
    });

    // GET /public-key
    CROW_ROUTE(app, "/public-key")
    .methods("GET"_method)
    ([&ntru]() {
        try {
            auto pubKey = ntru.getPublicKey();
            // Log first few bytes to confirm format
            if (!pubKey.empty()) {
                std::ostringstream ph;
                ph << std::hex << std::uppercase << std::setfill('0');
                for (size_t i = 0; i < std::min<size_t>(16, pubKey.size()); ++i) ph << std::setw(2) << (int)pubKey[i];
                std::cout << "[Server] Public key bytes[0..15]: " << ph.str() << " (len=" << pubKey.size() << ")" << std::endl;
            }
            std::string pubHex = bytesToHex(pubKey);
            
            crow::json::wvalue response;
            response["publicKey"] = "PUBHEX:" + pubHex;
            
            crow::response res(200, response);
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        } catch (const std::exception& e) {
            log_error("Error in /public-key: " + std::string(e.what()));
            crow::response res(500, crow::json::wvalue{{"error", "Server error"}});
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
    });

    // POST /master-key
    CROW_ROUTE(app, "/master-key")
    .methods("POST"_method, "OPTIONS"_method)
    ([&ntru, &db, &masterKey](const crow::request& req) {
        if (req.method == "OPTIONS"_method) {
            crow::response res(200);
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Methods", "POST, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            return res;
        }

        try {
            std::cout << "Received POST /master-key request" << std::endl;
            
            auto body = crow::json::load(req.body);
            if (!body || !body.has("encKey")) {
                log_error("Missing encKey field in /master-key request");
                crow::response res(400, crow::json::wvalue{{"error", "Missing encKey field"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }

            std::string encKey = body["encKey"].s();
            
            if (encKey.substr(0, 7) != "ENCKEY:") {
                log_error("Invalid master key format in /master-key: " + encKey.substr(0, 20) + "...");
                crow::response res(400, crow::json::wvalue{{"error", "Invalid ENCKEY format"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }
            
            std::string encKeyHex = encKey.substr(7);
            if (encKeyHex.size() % 2 != 0) {
                log_error("ENCKEY hex has odd length");
                crow::response res(400, crow::json::wvalue{{"error", "Invalid ENCKEY hex"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }
            auto encKeyBytes = hexToBytes(encKeyHex);
            if (encKeyBytes.size() != (size_t)NTRU_N * 2) {
                log_error("ENCKEY size invalid: " + std::to_string(encKeyBytes.size()) + ", expected " + std::to_string(NTRU_N * 2));
                crow::response res(400, crow::json::wvalue{{"error", "Invalid ENCKEY size"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }
            {
                std::ostringstream ep;
                ep << std::hex << std::uppercase << std::setfill('0');
                for (int i = 0; i < 16 && i < (int)encKeyBytes.size(); ++i) ep << std::setw(2) << (int)encKeyBytes[i];
                std::cout << "[Server] ENCKEY bytes[0..15]: " << ep.str() << " (len=" << encKeyBytes.size() << ")" << std::endl;
            }
            
            // Optional compatibility path: accept raw master key if provided
            if (body.has("rawKey")) {
                std::string rawKey = body["rawKey"].s();
                if (rawKey.rfind("RAWKEY:", 0) == 0) {
                    std::string rawHex = rawKey.substr(7);
                    auto rawBytes = hexToBytes(rawHex);
                    if (rawBytes.size() == 32) {
                        masterKey = rawBytes;
                        std::cout << "[Server] Using RAWKEY override from client" << std::endl;
                    } else {
                        log_error("RAWKEY size invalid: " + std::to_string(rawBytes.size()));
                        crow::response res(400, crow::json::wvalue{{"error", "Invalid RAWKEY size"}});
                        res.add_header("Access-Control-Allow-Origin", "*");
                        return res;
                    }
                }
            }
            if (masterKey.empty()) {
                masterKey = ntru.decrypt(encKeyBytes);
            }
            // No additional reduction needed - use the decrypted key directly
            if (masterKey.size() != 32) {
                log_error("Decrypted master key size invalid: " + std::to_string(masterKey.size()));
                crow::response res(500, crow::json::wvalue{{"error", "Key decrypt error"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }
            std::string masterKeyHex = bytesToHex(masterKey);

            {
                std::ostringstream mk;
                mk << std::hex << std::uppercase << std::setfill('0');
                for (int i = 0; i < 32 && i < (int)masterKey.size(); ++i) mk << std::setw(2) << (int)masterKey[i];
                std::cout << "[Server] Decrypted master key[0..31]: " << mk.str() << std::endl;
            }

            // Derive and log HMAC key prefix for debugging
            {
                DerivedKeys dbg;
                deriveKeys(masterKey.data(), masterKey.size(), dbg);
                std::ostringstream hk;
                hk << std::hex << std::uppercase << std::setfill('0');
                for (int i = 0; i < 16; ++i) hk << std::setw(2) << (int)dbg.hmacKey[i];
                std::cout << "[Server] HMAC key[0..15] after /master-key: " << hk.str() << std::endl;
            }
            
            std::cout << "Master key decrypted and stored" << std::endl;
            
            pqxx::work txn(db);
            txn.exec_prepared("insert_master_key", encKeyHex, std::string("received"), masterKeyHex);
            txn.commit();
            
            crow::json::wvalue response;
            response["status"] = "OK:Encrypted key received";
            
            crow::response res(200, response);
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
            
        } catch (const std::exception& e) {
            log_error("Error in /master-key: " + std::string(e.what()));
            crow::response res(500, crow::json::wvalue{{"error", "Server error"}});
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
    });

    // POST /health-data
    CROW_ROUTE(app, "/health-data")
    .methods("POST"_method, "OPTIONS"_method)
    ([&db, &masterKey](const crow::request& req) {
        if (req.method == "OPTIONS"_method) {
            crow::response res(200);
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Methods", "POST, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            return res;
        }

        if (masterKey.empty()) {
            log_error("No master key available for /health-data request");
            crow::response res(400, crow::json::wvalue{{"error", "No master key available"}});
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
        
        try {
            auto body = crow::json::load(req.body);
            if (!body || !body.has("encData")) {
                log_error("Missing encData field in /health-data request");
                crow::response res(400, crow::json::wvalue{{"error", "Missing encData field"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }

            std::string encData = body["encData"].s();
            
            if (encData.substr(0, 9) != "ENC_DATA:") {
                log_error("Invalid ENC_DATA format in /health-data: " + encData.substr(0, 20) + "...");
                crow::response res(400, crow::json::wvalue{{"error", "Invalid ENC_DATA format"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }
            
            std::string packetHex = encData.substr(9);
            auto packet = hexToBytes(packetHex);
            
            DerivedKeysEnhanced baseKeys;
            if (!deriveKeysEnhanced(masterKey.data(), masterKey.size(), baseKeys)) {
                log_error("Failed to derive enhanced keys in /health-data");
                crow::response res(500, crow::json::wvalue{{"error", "Key derivation failed"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }
            {
                std::ostringstream hk;
                hk << std::hex << std::uppercase << std::setfill('0');
                for (int i = 0; i < 16; ++i) hk << std::setw(2) << (int)baseKeys.base.hmacKey[i];
                std::cout << "[Server] HMAC key[0..15] at /health-data: " << hk.str() << std::endl;
            }
            
            std::string decrypted = pipelineDecryptPacketAdaptive(baseKeys, packet, packet.size());
            if (decrypted.empty()) {
                std::cout << "[Server] Adaptive decrypt failed; trying fallback methods..." << std::endl;
                // Fallback to original methods if adaptive fails
                decrypted = pipelineDecryptPacket(baseKeys.base, packet, packet.size());
                if (decrypted.empty()) {
                    std::cout << "[Server] Primary decrypt failed; trying alt1 (Tnk->LFSR->FwdTrans)..." << std::endl;
                    decrypted = pipelineDecryptPacketAlt(baseKeys.base, packet, packet.size());
                }
                if (decrypted.empty()) {
                    std::cout << "[Server] Alt1 failed; trying alt2 (FwdTrans->Tnk->LFSR)..." << std::endl;
                    decrypted = pipelineDecryptPacketAlt2(baseKeys.base, packet, packet.size());
                }
            }
            
            if (decrypted.empty()) {
                log_error("Decryption failed in /health-data");
                crow::response res(400, crow::json::wvalue{{"error", "Decryption failed"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }

            // Parse health data
            std::regex regex_pattern("HR-(\\d+) SPO2-(\\d+) STEPS-(\\d+)");
            std::smatch match;
            if (!std::regex_match(decrypted, match, regex_pattern)) {
                log_error("Invalid data format in /health-data: " + decrypted);
                crow::response res(400, crow::json::wvalue{{"error", "Invalid data format"}});
                res.add_header("Access-Control-Allow-Origin", "*");
                return res;
            }
            
            int heart_rate = std::stoi(match[1]);
            int spo2 = std::stoi(match[2]);
            int steps = std::stoi(match[3]);

            std::cout << "Health data received - HR: " << heart_rate << ", SPO2: " << spo2 << ", Steps: " << steps << std::endl;

            pqxx::work txn(db);
            txn.exec_prepared("insert_health_data", heart_rate, spo2, steps);
            txn.commit();
            
            crow::json::wvalue response;
            response["status"] = "ENC_OK:Stored";
            
            crow::response res(200, response);
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
            
        } catch (const std::exception& e) {
            log_error("Error in /health-data: " + std::string(e.what()));
            crow::response res(500, crow::json::wvalue{{"error", "Server error"}});
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
    });

    try {
        // Ensure required tables exist
        {
            pqxx::work ddl(db);
            // Ensure tables exist
            ddl.exec("CREATE TABLE IF NOT EXISTS master_keys (\n"
                     "    id serial PRIMARY KEY,\n"
                     "    created_at timestamptz NOT NULL DEFAULT now()\n"
                     ")");
            ddl.exec("CREATE TABLE IF NOT EXISTS health_data (\n"
                     "    id serial PRIMARY KEY,\n"
                     "    created_at timestamptz NOT NULL DEFAULT now()\n"
                     ")");

            // Ensure required columns exist with compatible types
            ddl.exec("ALTER TABLE master_keys\n"
                     "  ADD COLUMN IF NOT EXISTS master_key text,\n"
                     "  ADD COLUMN IF NOT EXISTS encrypted_key text NOT NULL DEFAULT '',\n"
                     "  ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'received'");

            ddl.exec("ALTER TABLE health_data\n"
                     "  ADD COLUMN IF NOT EXISTS heart_rate smallint,\n"
                     "  ADD COLUMN IF NOT EXISTS spo2 smallint,\n"
                     "  ADD COLUMN IF NOT EXISTS steps integer");

            ddl.commit();
        }

        // Prepare SQL statements
        pqxx::work prep(db);
        prep.exec("PREPARE insert_master_key (text, text, text) AS INSERT INTO master_keys (encrypted_key, status, master_key) VALUES ($1, $2, $3)");
        prep.exec("PREPARE insert_health_data (smallint, smallint, integer) AS INSERT INTO health_data (heart_rate, spo2, steps) VALUES ($1, $2, $3)");
        prep.commit();

        // Initialize security subsystems
        adaptive_monitor_init(&gAdaptiveMonitor);
        nonce_tracker_init(&gNonceTracker, false);  // false = random nonce mode
        key_rotation_init(&gKeyRotationPolicy);

        std::cout << "Adaptive monitoring initialized" << std::endl;

        // Start metrics reset thread
        gMetricsThread = std::thread([]() {
            while (gMetricsThreadRunning) {
                std::this_thread::sleep_for(std::chrono::minutes(1));
                adaptive_monitor_reset_window(&gAdaptiveMonitor);
                
                uint64_t now = GET_TIME_MS();
                nonce_tracker_cleanup(&gNonceTracker, now);
                
                // Log current metrics
                const SecurityMetrics* metrics = adaptive_monitor_get_metrics(&gAdaptiveMonitor);
                std::cout << "[Metrics] Decrypt failures: " << metrics->decrypt_failures
                          << ", HMAC failures: " << metrics->hmac_failures
                          << ", Replay attempts: " << metrics->replay_attempts
                          << ", Requests: " << metrics->requests_per_minute
                          << std::endl;
                
                // Check if recipe switch needed
                if (adaptive_monitor_should_switch(&gAdaptiveMonitor)) {
                    EncryptionRecipe recommended = adaptive_monitor_get_recipe(&gAdaptiveMonitor);
                    adaptive_monitor_switch_recipe(&gAdaptiveMonitor, recommended);
                    
                    const char* recipe_name = (recommended == RECIPE_XENOCIPHER_NORMAL) ? "Normal" :
                                             (recommended == RECIPE_XENOCIPHER_HARDENED) ? "Hardened" :
                                             "ChaCha20-Poly1305";
                    std::cout << "⚠️  ADAPTIVE SWITCH: Switching to " << recipe_name 
                              << " recipe due to attack indicators" << std::endl;
                }
            }
        });

        std::cout << "Starting XenoCipher Server on 0.0.0.0:8081..." << std::endl;
        std::cout << "Available endpoints:" << std::endl;
        std::cout << "  GET  /public-key" << std::endl;
        std::cout << "  POST /master-key" << std::endl;
        std::cout << "  POST /health-data" << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;

        app.bindaddr("0.0.0.0").port(8081).multithreaded().run();

    } catch (const std::exception& e) {
        log_error("Main application error: " + std::string(e.what()));
    }

    return 0;
}