
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "c10_data.h"
#include "utils.h"

int ecb128(unsigned char *input, unsigned char *output, unsigned char *iv, unsigned char *key, int do_encrypt)
{
  int outlen;
  // new'ing and freeing the context seems wasteful, since I never
  // re-use it. Is there a simpler way to do ecb?
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  // "add" iv to the input before sending to the cipher core.
  EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL, do_encrypt);
  int success = EVP_CipherUpdate(ctx, output, &outlen, input, 16);
  repeating_xor_decode(output, iv, 16);
  EVP_CIPHER_CTX_free(ctx);
  return success;
}

void print16(unsigned char *data)
{
  for (int i = 0; i < 16; ++i) {
    printf("%02X ", data[i]);
  }
  printf("  ");
  for (int i = 0; i < 16; ++i) {
    printf("%c", isprint(data[i]) ? data[i] : '.');
  }
  printf("\n");
}

void main(void)
{
  unsigned char key[] = "YELLOW SUBMARINE";
  unsigned char iv[16] = {'\0',};
  unsigned char decrypted[17] = {'\0',};

  size_t data_size;
  unsigned char *data = base64_decode(base64_data, &data_size);
  printf("input length: %lu\n", data_size);

  print16(key);

  for (int i = 0; i < data_size; i += 16) {
    ecb128(data + i, decrypted, i == 0 ? iv : data + i - 16, key, 0);
    print16(decrypted);
  }
}

