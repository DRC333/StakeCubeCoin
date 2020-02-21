void setKey(uint256* key);
uint256* getKey();
void setIVKey(uint64_t* key);
uint64_t* getIVKey();
void calculateIVKey(uint64_t& key);
bool decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int *plaintext_len);
bool encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int *ciphertext_len);

