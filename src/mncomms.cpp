#include "main.h"
#include "util.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

uint256 Key = 0;
uint64_t ivKey = 0;

void setKey(uint256* key)
{
    Key = *key;
}

uint256* getKey()
{
    return &Key;
}

void setIVKey(uint64_t* key)
{
    ivKey = *key;
}

uint64_t* getIVKey()
{
    return &ivKey;
}

void calculateIVKey(uint64_t& key)
{
    //! determine bounds
    int startRange = chainActive.Height();
    int testRange = startRange;
    while (testRange > ((startRange / 100) * 100)) { testRange--; }
    startRange = testRange - 1000;

    //! calculate modifier
    uint64_t hashMix = 0;
    uint256 blockHash = uint256(0);
    CBlockIndex* pblockindex = nullptr;
    for (unsigned int i=0; i < 768; i++) {
       pblockindex = chainActive[startRange+i];
       blockHash = pblockindex->GetBlockHash();
       uint64_t *partialHash = (uint64_t*)&blockHash;
       hashMix += *partialHash;
    }

    //! store and confirm init
    uint256 startHash = chainActive[startRange]->GetBlockHash();
    setKey(&startHash);
    setIVKey(&hashMix);
    if (!g_mncomms_init)
        g_mncomms_init = true;

    //! debug
    LogPrintf("- using block offset %d (key: %s, iv: %016llx)\n", startRange, startHash.ToString().c_str(), hashMix);
    return;
}

bool decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int *plaintext_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;

    if(!(ctx = EVP_CIPHER_CTX_new())) return false;
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return false;
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return false;
    plaintext_len = &len;

    if(!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return false;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int *ciphertext_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;

    if(!(ctx = EVP_CIPHER_CTX_new())) return false;
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return false;
    if(!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return false;
    ciphertext_len = &len;

    if(!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return false;
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

