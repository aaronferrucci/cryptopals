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
  *out_len = len;

  for (int i = 0; i < in_len; ++i)
    plaintext[i] = input[i];
  for (int i = 0; i < unknown_string_len; ++i)
    plaintext[i + in_len] = unknown_string[i];
  for (int i = 0; i < strlen(padding); ++i) 
    plaintext[i + in_len + unknown_string_len] = padding[i];
  free(padding);

  ecb128_encrypt(plaintext, output, len, key);
  free(plaintext);
  return output;
}

void deinit(void)
{
  if (unknown_string) free(unknown_string);
  unknown_string = NULL;
}

int find_block_size(void)
{
  int block_size = 0;
  unsigned char *text = malloc(128 * sizeof(unsigned char));
  for (int i = 0; i < 128; ++i)
    text[i] = 'A';
  size_t prev_len = 0;
  for (int i = 1; i < 128; ++i) {
    size_t out_len;
    unsigned char *output = insecure_ecb(text, i, &out_len);
    free(output);
    if (prev_len) {
      if (prev_len != out_len) {
        block_size = (int)(out_len - prev_len);
        break;
      }
    }
    prev_len = out_len;
  }
  free(text);
  return block_size;
}

int main(void)
{
  printf("challenge12\n");
  init();

  // 1. Feed identical bytes of your-string to the function 1 at a time --- 
  // start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover 
  // the block size of the cipher. You know it, but do this step anyway.
  int block_size = find_block_size();
  printf("block size: %d\n", block_size);

  // 2. Detect that the function is using ECB. You already know, but do this 
  // step anyway.
  // 3. Knowing the block size, craft an input block that is exactly 1 byte 
  // short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think 
  // about what the oracle function is going to put in that last byte position.
  // 4. Make a dictionary of every possible last byte by feeding different 
  // strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", 
  // remembering the first block of each invocation.
  // 5. Match the output of the one-byte-short input to one of the entries 
  // in your dictionary. You've now discovered the first byte of unknown-string.
  // 6. Repeat for the next byte.

  deinit();
}

