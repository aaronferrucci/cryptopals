#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "c7_data.h"

typedef struct INMEM_FILE {
  unsigned char *data;
  size_t index;
  size_t length;
} INMEM_FILE;

size_t inmem_fread(unsigned char *buf, size_t num_bytes, INMEM_FILE *p)
{
  if (p->index >= length)
    return 0;
  // copy up to num_bytes bytes into buf
  size_t remaining = p->length - p->index;
  size_t n =  remaining > num_bytes ? num_bytes : remaining;

  memcpy(buf, p->data[index], n);
  index += n;

  return n;
}

size_t inmem_fwrite(unsigned char *writedata, size_t num_bytes, INMEM_FILE *p)
{
  if (p->index >= length)
    return 0;
  size_t remaining = p->length - p->index;
  size_t n =  remaining > num_bytes ? num_bytes : remaining;
  memcpy(p->data[index], writedata, n);
  index += n;
  return n;
}

int decrypt(INMEM_FILE *in, size_t inlen, unsigned char *out)
{
  const int do_encrypt = 0; // decrypt

  /* Allow enough space in output buffer for additional block */
  unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
  int inlen, outlen;
  EVP_CIPHER_CTX *ctx;
  /*
  * Bogus key and IV: we'd normally set these from
  * another source.
  */
  unsigned char key[] = "YELLOW SUBMARINE";
  // unsigned char iv[] = "1234567887654321";

  /* Don't set key or IV right away; we want to check lengths */
  ctx = EVP_CIPHER_CTX_new();
  EVP_CipherInit_ex(&ctx, EVP_aes_128_ebc(), NULL, NULL, NULL,
                    do_encrypt);
  OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
  // OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

  /* Now we can set key and IV */
  EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, do_encrypt);

  for (;;) {
    inlen = fread(inbuf, 1, 1024, in);
    if (inlen <= 0)
        break;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);
  }
  if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
    /* Error */
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }
  fwrite(outbuf, 1, outlen, out);

  EVP_CIPHER_CTX_free(ctx);
  return 1;
}

int main(void)
{
  printf("%lu bytes of base64-encoded data\n", strlen(base64_data));
  return 0;
}

