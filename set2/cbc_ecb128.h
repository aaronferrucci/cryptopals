#ifndef CBC_ECB128_H
#define CBC_ECB128_H
int cbc_or_ecb128(unsigned char *input, unsigned char *output, unsigned char *iv, unsigned char *key, int do_encrypt, int is_cbc);
int cbc128(unsigned char *input, unsigned char *output, unsigned char *iv, unsigned char *key, int do_encrypt);
int ecb128(unsigned char *input, unsigned char *output, unsigned char *iv, unsigned char *key, int do_encrypt);
int cbc128_decrypt(unsigned char *input, unsigned char *output, size_t len, unsigned char *iv, unsigned char *key);
#endif // CBC_ECB128_H
