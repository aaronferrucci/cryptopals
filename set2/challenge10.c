
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "c10_data.h"
#include "inmem_file.h"

int encrypt(INMEM_FILE *in, INMEM_FILE *out, unsigned char *key, unsigned char *iv)
{
  const int do_encrypt = 1; // encrypt

  /* Allow enough space in output buffer for additional block */
  unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
  int inlen, outlen;
  EVP_CIPHER_CTX *ctx;
  /*
  * Bogus key and IV: we'd normally set these from
  * another source.
  */

  /* Don't set key or IV right away; we want to check lengths */
  ctx = EVP_CIPHER_CTX_new();
  EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, NULL, NULL,
                    do_encrypt);
  OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
  // OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

  /* Now we can set key and IV */
  EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

  for (;;) {
    inlen = inmem_fread(inbuf, 1024, in);
    if (inlen <= 0)
        break;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    inmem_fwrite(outbuf, outlen, out);
  }
  if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
    /* Error */
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }
  inmem_fwrite(outbuf, outlen, out);

  EVP_CIPHER_CTX_free(ctx);
  return 1;
}


