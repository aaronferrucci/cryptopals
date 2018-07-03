#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>

#include "cbc_ecb128.h"
#include "utils.h"

static unsigned char unknown_string_base64[] = 
  "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
  "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
  "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
  "YnkK";
static unsigned char *unknown_string = NULL;
static size_t unknown_string_len;

static unsigned char key[16] = {'\0',};

// will malloc space for the output. Caller is responsible to free().
unsigned char *pad(size_t len, size_t block_size)
{
  size_t pad_size = block_size - (len % block_size);

  unsigned char *pad = malloc((1 + pad_size) * sizeof(unsigned char));
  unsigned char *pret = pad;
  for (int i = 0; i < pad_size; ++i)
    *pad++ = (unsigned char)pad_size;
  *pad++ = '\0';
  return pret;
}

void init()
{
  // one-time setup
  if (unknown_string == NULL) {
    unknown_string = base64_decode(unknown_string_base64, &unknown_string_len);
  }
  while (!key[0]) {
    random16(key);
  }
}

// aes-128-ecb(input || unknown_string, key)
// mallocs the return string; caller must free
unsigned char *insecure_ecb(unsigned char *input, size_t in_len, size_t *out_len)
{
  unsigned char *padding = pad(in_len + unknown_string_len, 16);
  size_t len = in_len + unknown_string_len + strlen(padding);
  unsigned char *plaintext = malloc(len * sizeof(unsigned char));
  unsigned char *output = malloc(len * sizeof(unsigned char));

  for (int i = 0; i < in_len; ++i)
    plaintext[i] = input[i];
  for (int i = 0; i < unknown_string_len; ++i)
    plaintext[i + in_len] = unknown_string[i];
  for (int i = 0; i < strlen(padding); ++i) 
    plaintext[i + in_len + unknown_string_len] = padding[i];
  free(padding);

  // to do: encrypt plaintext into output
  // free plaintext
  // return output (caller must free)
  return output;
}

void deinit(void)
{
  if (unknown_string) free(unknown_string);
  unknown_string = NULL;
}

int main(void)
{
  size_t out_len;
  printf("challenge12\n");
  init();

  unsigned char *output = insecure_ecb("A", 1, &out_len);
  free(output);

  deinit();
}

