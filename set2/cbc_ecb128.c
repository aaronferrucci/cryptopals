#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "utils.h"

int cbc_or_ecb128(unsigned char *input, unsigned char *output, unsigned char *iv, unsigned char *key, int do_encrypt, int is_cbc)
{
  int outlen;
  // new'ing and freeing the context seems wasteful, since I never
  // re-use it. Is there a simpler way to do ecb?
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  // "add" iv to the input before sending to the cipher core.
  if (is_cbc && do_encrypt) {
    repeating_xor_decode(input, iv, 16);
  }
  EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL, do_encrypt);
  // undo the input XOR (don't want to change the caller's data)
  if (is_cbc && do_encrypt) {
    repeating_xor_decode(input, iv, 16);
  }
  int success = EVP_CipherUpdate(ctx, output, &outlen, input, 16);
  if (is_cbc && !do_encrypt)
    repeating_xor_decode(output, iv, 16);
  EVP_CIPHER_CTX_free(ctx);
  return success;
}

int cbc128(unsigned char *input, unsigned char *output, unsigned char *iv, unsigned char *key, int do_encrypt)
{
  return cbc_or_ecb128(input, output, iv, key, do_encrypt, 1);
}

int ecb128(unsigned char *input, unsigned char *output, unsigned char *iv, unsigned char *key, int do_encrypt)
{
  return cbc_or_ecb128(input, output, iv, key, do_encrypt, 0);
}

int cbc128_decrypt(unsigned char *input, unsigned char *output, size_t len, unsigned char *iv, unsigned char *key)
{
  int ret = 1;
  for (int i = 0; i < len; i += 16) {
    ret &= cbc128(input + i, output + i, i == 0 ? iv : input + i - 16, key, 0);
  }
  return ret;
}

