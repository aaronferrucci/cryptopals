#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>

#include "cbc_ecb128.h"
#include "utils.h"

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

// Write a function to generate a random AES key; that's just 16 random bytes.
// Write a function that encrypts data under an unknown key --- that is,
// a function that generates a random key and encrypts under it.
//
// The function should look like:
//
// encryption_oracle(your-input)
// => [MEANINGLESS JIBBER JABBER]
// Under the hood, have the function append 5-10 bytes (count chosen 
// randomly) before the plaintext and 5-10 bytes after the plaintext.
// 
// Now, have the function choose to encrypt under ECB 1/2 the time, and 
// under CBC the other half (just use random IVs each time for CBC). Use 
// rand(2) to decide which to use.
// 
// Detect the block cipher mode the function is using each time. You 
// should end up with a piece of code that, pointed at a block box that 
// might be encrypting ECB or CBC, tells you which one is happening.

#define ITERS 1024
// returns the data, padded and encrypted. Caller frees.
unsigned char actual_log[ITERS];
unsigned char *pad_and_encrypt(unsigned char *data, size_t *len)
{
  static int log_index = 0;
  unsigned char key[16];
  unsigned char iv[16];
  size_t prefix, suffix;
  random16(key);
  random16(iv);

  prefix = (rand() % 6) + 5;
  suffix = (rand() % 6) + 5;
  // printf("prefix: %d\n", prefix);

  unsigned char *padding = pad(prefix + *len + suffix, 16);
  size_t aug_len = prefix + *len + suffix + strlen(padding);
  unsigned char *plaintext = malloc(aug_len * sizeof(unsigned char));
  unsigned char *output = malloc(aug_len * sizeof(unsigned char));

  randomX(plaintext, prefix);
  randomX(plaintext + prefix + *len, suffix);
  for (int i = prefix; i < prefix + *len; ++i) {
    plaintext[i] = data[i - prefix];
  }
  for (int i = prefix + *len + suffix; i < aug_len; ++i) {
    plaintext[i] = padding[i - prefix - *len - suffix];
  }
  free(padding);
  // printf("plaintext:\n");
  // printX(plaintext, *len);

  // encrypt "plaintext"
  int is_cbc = rand() & 1;
  if (log_index < ITERS)
    actual_log[log_index++] = is_cbc;

  if (is_cbc) {
    cbc128_encrypt(plaintext, output, aug_len, iv, key);
  } else {
    ecb128_encrypt(plaintext, output, aug_len, key);
  }
  free(plaintext);

  *len = aug_len;
  return output;
}

// mallocs the data; caller calls free
unsigned char *random_data(size_t len)
{
  // get 16 random bytes
  // replicate the random bytes over the output
  unsigned char rand16[16];
  random16(rand16);

  unsigned char *data = malloc(len * sizeof(unsigned char));
  int i = 0;
  while (i < len) {
    data[i] = rand16[i % 16];
    ++i;
  }
  return data;
}

// return:
// 0 if ecb encryption (16-byte blocks) detected
// 1 otherwise (assume cbc)
unsigned char detect_encryption_method(unsigned char *crypt)
{
  // given prefix padding of 5-10 bytes, the first block will be different
  // from subsequent blocks. But starting at block number 1 (2nd block), given
  // replicated input data, output data is identical.
  // if (11+16)th, (11+32)th, (11+48)th bytes are identical, assume ecb.
  // odds should be 1 in 256^2 of a false positive (cbc matching that test)
  const int blocksize = 16;
  if (crypt[blocksize] == crypt[2*blocksize] &&
      crypt[blocksize] == crypt[3*blocksize] &&
      crypt[blocksize] == crypt[4*blocksize])
    return 0;
  return 1;
}

#define LEN 256
int main(void)
{
  unsigned char predicted_log[ITERS] = {'\0',};
  srand(time(NULL));
  int pred_index = 0;
  for (int i = 0; i < ITERS; ++i) {
    unsigned char *data = random_data(LEN);
    // printf("data:\n");
    // printX(data, LEN);

    unsigned char *output;
    size_t len = LEN;
    output = pad_and_encrypt(data, &len);
    free(data);

    // printf("output (%lu):\n", len);
    // printX(output, len);
    unsigned char pred = detect_encryption_method(output);
    predicted_log[pred_index++] = pred;
    free(output);
  }

  // Compare actual and predicted
  unsigned int errors = 0;
  for (int i = 0; i < ITERS; ++i) {
    if (predicted_log[i] != actual_log[i]) {
      printf("mismatch at index %d (predicted: %d; actual: %d)\n",
        i, predicted_log[i], actual_log[i]);
      errors++;
    }
  }
  printf("%d errors out of %d tests\n", errors, ITERS);

  return errors;
}

