#ifndef SALSA20_IMPL_H
#define SALSA20_IMPL_H

#include <cstdint>
#include <cstring>

class Salsa20 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 8;
    static constexpr size_t BLOCK_SIZE = 64;
    
    Salsa20();
    
    void init(const uint8_t* key, size_t keyLen,
              const uint8_t* nonce, size_t nonceLen);
    
    void encrypt(const uint8_t* plaintext, uint8_t* ciphertext, size_t len);
    void decrypt(const uint8_t* ciphertext, uint8_t* plaintext, size_t len);
    
private:
    uint32_t state[16];
    uint32_t counter;
    uint8_t keystream[BLOCK_SIZE];
    size_t keystreamPos;
    
    void salsa20Block();
    static uint32_t rotl32(uint32_t x, uint32_t n);
};

#endif // SALSA20_IMPL_H
