
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "c10_data.h"
#include "utils.h"

int block_crypt(unsigned char *input, unsigned char *output, unsigned char *iv, unsigned char *key, int do_encrypt)
{
  EVP_CIPHER_CTX *ctx;
  int outlen;
  ctx = EVP_CIPHER_CTX_new();
  EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL, do_encrypt);
  if (!EVP_CipherUpdate(ctx, output, &outlen, input, 16)) {
    /* Error */
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }
  EVP_CIPHER_CTX_free(ctx);
  return 1;
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
  unsigned char iv[16] = {'\xAA',};
  unsigned char plain[] = "abcdefghijklmnop"; 
  unsigned char encrypted[17] = {'\0',};
  unsigned char decrypted[17] = {'\0',};

  print16(key);

/*
  block_crypt(plain, encrypted, iv, key, 1);
  print16(encrypted);

  block_crypt(encrypted, decrypted, iv, key, 0);
  print16(decrypted);
*/

  size_t data_size;
  unsigned char *data = base64_decode(base64_data, &data_size);
  block_crypt(data, decrypted, iv, key, 0);
  print16(decrypted);
}


