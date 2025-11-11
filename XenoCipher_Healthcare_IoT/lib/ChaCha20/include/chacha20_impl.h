#ifndef CHACHA20_IMPL_H
#define CHACHA20_IMPL_H

#include <cstdint>
#include <cstring>
#include <vector>

class ChaCha20 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t BLOCK_SIZE = 64;
    
    ChaCha20();
    
    // Initialize with key and nonce
    void init(const uint8_t* key, size_t keyLen,
              const uint8_t* nonce, size_t nonceLen);
    
    // Encrypt/decrypt (stream cipher)
    void encrypt(const uint8_t* plaintext, uint8_t* ciphertext, size_t len);
    void decrypt(const uint8_t* ciphertext, uint8_t* plaintext, size_t len);
    
    // Generate raw keystream
    void generateKeystream(uint8_t* keystream, size_t len);
    
private:
    uint32_t state[16];
    uint32_t counter;
    uint8_t keystream[BLOCK_SIZE];
    size_t keystreamPos;
    
    void chacha20Block();
    void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    static uint32_t rotl32(uint32_t x, uint32_t n);
};

#endif // CHACHA20_IMPL_H
