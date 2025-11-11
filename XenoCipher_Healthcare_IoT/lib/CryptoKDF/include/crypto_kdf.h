// crypto_kdf.h - KDF with domain separation

#ifndef CRYPTO_KDF_H
#define CRYPTO_KDF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef KDF_ITERATIONS
// Not used by HKDF, but keep for compatibility if you want PBKDF2 fallback
#define KDF_ITERATIONS 5000
#endif

// Domain-separated key derivation labels (enforced at compile time)
#define KDF_LABEL_LFSR_SEED         "xenocipher-lfsr-seed-v1"
#define KDF_LABEL_TINKERBELL        "xenocipher-tinkerbell-v1"
#define KDF_LABEL_TRANSPOSITION     "xenocipher-transposition-v1"
#define KDF_LABEL_HMAC              "xenocipher-hmac-key-v1"
#define KDF_LABEL_CHACHA20          "xenocipher-chacha20-v1"
#define KDF_LABEL_MESSAGE_BASE      "xenocipher-message-keys-v1"
#define KDF_LABEL_ROTATION          "xenocipher-rotation-"

// Salt constants (must be consistent across device and server)
#define KDF_SALT_COMMON             "MPGeeks-HackersAreUnbeatableBoys"
#define KDF_SALT_ROTATION           "XENO-ROT-SALT-v1"

// Basic derived keys structure
struct DerivedKeys {
  uint32_t lfsrSeed;           // 32-bit seed (non-zero)
  uint8_t  tinkerbellKey[16];  // chaos key (16 bytes)
  uint8_t  transpositionKey[16];// transposition key (16 bytes)
  uint8_t  hmacKey[32];        // MAC key (32 bytes)
};

// Basic message keys structure
struct MessageKeys {
  uint32_t lfsrSeed;
  uint8_t  tinkerbellKey[16];
  uint8_t  transpositionKey[16];
};

/**
 * HKDF-SHA256 extract/expand helpers and high-level derive functions
 */
bool hkdf_extract(const uint8_t *salt, size_t saltLen,
                  const uint8_t *ikm, size_t ikmLen,
                  uint8_t prk[32]);

bool hkdf_expand(const uint8_t prk[32],
                 const uint8_t *info, size_t infoLen,
                 uint8_t *out, size_t outLen);

/**
 * deriveKeys: derive base keys from masterSecret (32..64 bytes recommended)
 * Uses HKDF-Extract(protocol_salt, masterSecret) as PRK and HKDF-Expand with
 * domain-separated info strings.
 */
bool deriveKeys(const uint8_t* masterSecret, size_t masterLen, struct DerivedKeys& out);

/**
 * deriveMessageKeys: derive per-message keys deterministically (no XOR mixing).
 * Uses HKDF-Expand(PRK, "xenocipher-message-keys-v1" || nonce_be32) where PRK is derived from base.hmacKey.
 *
 * Important: This function must produce independent per-message keys; caller must pass nonce.
 */
bool deriveMessageKeys(const struct DerivedKeys& base, uint32_t nonce, struct MessageKeys& out);

// Enhanced derived keys structure with domain separation
typedef struct {
    struct DerivedKeys base;        // Base XenoCipher keys
    uint8_t chacha20Key[32];        // 32 bytes - ChaCha20 fallback (optional)
} DerivedKeysEnhanced;

/**
 * deriveKeysEnhanced: derive enhanced keys including ChaCha20 key for fallback recipe
 */
bool deriveKeysEnhanced(const uint8_t* masterSecret, size_t masterLen, DerivedKeysEnhanced& out);

// Per-message derived keys (includes nonce binding)
typedef struct {
    uint32_t lfsrSeed;
    uint8_t tinkerbellKey[16];
    uint8_t transpositionKey[16];
    uint32_t nonce;                 // Nonce used for derivation
} MessageKeysEnhanced;

#ifdef __cplusplus
}
#endif
#endif // CRYPTO_KDF_H

