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

//! return binary equivalent
unsigned char binvalue(const char v)
{
	if(v >= '0' && v <= '9')
		return v-'0';

	if(v >= 'a' && v <= 'f')
		return v-'a'+10;

	return 0;
}

//! binary to hexstring
void hexlify(char *hex, const unsigned char *bin, int len)
{
    hex[0] = 0;
    for(int i=0; i < len; i++)
        sprintf(hex+strlen(hex), "%02x", bin[i]);
}

//! hexstring to binary
void binlify(unsigned char *bin, const char *hex)
{
    int len = strlen(hex);
    for(int i=0; i<len/2; i++)
        bin[i] = binvalue(hex[i*2])<<4 | binvalue(hex[i*2+1]);
}

//! encrypt plaintext (plaintext_len) into ciphertext
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, int &ciphertext_len)
{
    int len;

    //! iv
    unsigned char iv[16];
    uint64_t *storedIVKey = getIVKey();
    memcpy(iv,&storedIVKey,8);
    memcpy(iv+8,&storedIVKey,8);

    //! convert input into buffer
    unsigned char buffer[4096];
    memset(buffer,0,4096);
    hexlify((char *)buffer, (const unsigned char*)plaintext, plaintext_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (const unsigned char *)getKey(), iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, strlen((const char*)buffer));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

//! decrypt ciphertext (ciphertext_len) into plaintext
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int &plaintext_len)
{
    int len;

    //! iv
    unsigned char iv[16];
    uint64_t *storedIVKey = getIVKey();
    memcpy(iv,&storedIVKey,8);
    memcpy(iv+8,&storedIVKey,8);

    //! convert input into buffer
    unsigned char buffer[4096];
    memset(buffer,0,4096);
    binlify(buffer, (const char*)ciphertext);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (const unsigned char *)getKey(), iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, buffer, 8+ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

