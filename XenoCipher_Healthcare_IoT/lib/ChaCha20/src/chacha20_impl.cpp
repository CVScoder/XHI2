#include "chacha20_impl.h"
#include <cstring>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

ChaCha20::ChaCha20() : counter(0), keystreamPos(BLOCK_SIZE) {
    memset(state, 0, sizeof(state));
    memset(keystream, 0, sizeof(keystream));
}

void ChaCha20::init(const uint8_t* key, size_t keyLen,
                    const uint8_t* nonce, size_t nonceLen) {
    if (keyLen != KEY_SIZE || nonceLen != NONCE_SIZE) {
        return;
    }
    
    // ChaCha20 constants
    state[0] = 0x61707865;  // "expa"
    state[1] = 0x3320646e;  // "nd 3"
    state[2] = 0x79622d32;  // "2-by"
    state[3] = 0x6b206574;  // "te k"
    
    // 256-bit key
    for (int i = 0; i < 8; i++) {
        state[4 + i] = (key[4*i] | (key[4*i+1] << 8) |
                       (key[4*i+2] << 16) | (key[4*i+3] << 24));
    }
    
    // Counter
    state[12] = 0;
    
    // 96-bit nonce (IETF)
    state[13] = (nonce[0] | (nonce[1] << 8) | (nonce[2] << 16) | (nonce[3] << 24));
    state[14] = (nonce[4] | (nonce[5] << 8) | (nonce[6] << 16) | (nonce[7] << 24));
    state[15] = (nonce[8] | (nonce[9] << 8) | (nonce[10] << 16) | (nonce[11] << 24));
    
    counter = 0;
    keystreamPos = BLOCK_SIZE;
}

void ChaCha20::quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = ROTL32(d, 16);
    c += d; b ^= c; b = ROTL32(b, 12);
    a += b; d ^= a; d = ROTL32(d, 8);
    c += d; b ^= c; b = ROTL32(b, 7);
}

void ChaCha20::chacha20Block() {
    uint32_t working[16];
    memcpy(working, state, sizeof(state));
    
    for (int i = 0; i < 10; i++) {
        // Column rounds
        quarterRound(working[0], working[4], working[8], working[12]);
        quarterRound(working[1], working[5], working[9], working[13]);
        quarterRound(working[2], working[6], working[10], working[14]);
        quarterRound(working[3], working[7], working[11], working[15]);
        
        // Diagonal rounds
        quarterRound(working[0], working[5], working[10], working[15]);
        quarterRound(working[1], working[6], working[11], working[12]);
        quarterRound(working[2], working[7], working[8], working[13]);
        quarterRound(working[3], working[4], working[9], working[14]);
    }
    
    for (int i = 0; i < 16; i++) {
        working[i] += state[i];
        uint32_t val = working[i];
        keystream[4*i] = val & 0xFF;
        keystream[4*i+1] = (val >> 8) & 0xFF;
        keystream[4*i+2] = (val >> 16) & 0xFF;
        keystream[4*i+3] = (val >> 24) & 0xFF;
    }
    
    state[12]++;
    keystreamPos = 0;
}

void ChaCha20::generateKeystream(uint8_t* output, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (keystreamPos >= BLOCK_SIZE) {
            chacha20Block();
        }
        output[i] = keystream[keystreamPos++];
    }
}

void ChaCha20::encrypt(const uint8_t* plaintext, uint8_t* ciphertext, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (keystreamPos >= BLOCK_SIZE) {
            chacha20Block();
        }
        ciphertext[i] = plaintext[i] ^ keystream[keystreamPos++];
    }
}

void ChaCha20::decrypt(const uint8_t* ciphertext, uint8_t* plaintext, size_t len) {
    encrypt(ciphertext, plaintext, len);  // Same operation for stream ciphers
}

uint32_t ChaCha20::rotl32(uint32_t x, uint32_t n) {
    return ROTL32(x, n);
}
