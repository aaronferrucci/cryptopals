#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "c7_data.h"
#include "utils.h"

typedef struct INMEM_FILE {
  unsigned char *data;
  size_t cur_index;
  size_t size;
} INMEM_FILE;

size_t inmem_fread(unsigned char *buf, size_t num_bytes, INMEM_FILE *p)
{
  if (p->cur_index >= p->size)
    return 0; // no more data left to read

  // copy up to num_bytes bytes into buf
  size_t remaining = p->size - p->cur_index;
  size_t n =  remaining > num_bytes ? num_bytes : remaining;

  memcpy(buf, &p->data[p->cur_index], n);
  p->cur_index += n;

  return n;
}

size_t inmem_fwrite(unsigned char *writedata, size_t num_bytes, INMEM_FILE *p)
{
  if (p->cur_index >= p->size)
    return 0; // no more space left to write to

  // copy at most num_bytes bytes from writedata
  size_t remaining = p->size - p->cur_index;
  size_t n =  remaining > num_bytes ? num_bytes : remaining;

  memcpy(&p->data[p->cur_index], writedata, n);
  p->cur_index += n;

  return n;
}

// possible useful notes on ssl usage here:
// http://theshybulb.com/2015/10/10/use-openssl-c-library.html
//
int decrypt(INMEM_FILE *in, INMEM_FILE *out)
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
  unsigned char iv[] = "1234567887654321";

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

int main(void)
{
  unsigned char *raw;
  size_t raw_len;
  INMEM_FILE crypt, plain;
  printf("%lu bytes of base64-encoded data\n", strlen(base64_data));

  raw = base64_decode(base64_data, &raw_len);
  printf("%lu bytes of decoded data\n", raw_len);

  crypt.data = raw;
  crypt.cur_index = 0;
  crypt.size = raw_len;

  plain.size = raw_len + EVP_MAX_BLOCK_LENGTH;
  unsigned char *plaintext =
    (unsigned char*)malloc(sizeof(unsigned char) * plain.size);
  plain.data = plaintext;
  plain.cur_index = 0;

  decrypt(&crypt, &plain);

  plain.data[plain.cur_index++] = '\0';
  printf("after decryption, plaintext has size %lu\n", plain.cur_index);
  printf("\n'%s'\n", plain.data);

  free(raw); raw = NULL;
  free(plaintext); plaintext = NULL;
  return 0;
}

