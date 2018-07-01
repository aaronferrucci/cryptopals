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

unsigned char *randomX(unsigned char *data, size_t len)
{
  for (int i = 0; i < len; ++i) {
    data[i] = rand() & 0xFF;
  }
  
  return data;
}

unsigned char *random16(unsigned char data[16])
{
  return randomX(data, 16);
}

// returns the data, padded and encrypted. Caller frees.
unsigned char *pad_and_encrypt(unsigned char *data, size_t *len)
{
  unsigned char key[16];
  random16(key);
  size_t prefix, suffix;

  prefix = (rand() % 6) + 5;
  printf("prefix: %lu\n", prefix);
  suffix = (rand() % 6) + 5;
  printf("suffix: %lu\n", suffix);

  unsigned char *padding = pad(prefix + *len + suffix, 16);
  size_t aug_len = prefix + *len + suffix + strlen(padding);
  unsigned char *output = malloc(aug_len * sizeof(unsigned char));

  randomX(output, prefix);
  randomX(output + prefix + *len, suffix);
  for (int i = prefix; i < prefix + *len; ++i) {
    output[i] = data[i - prefix];
  }
  for (int i = prefix + *len + suffix; i < aug_len; ++i) {
    output[i] = padding[i - prefix - *len - suffix];
  }
  free(padding);

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

void main(void)
{
  unsigned char key[16];
  srand(time(NULL));

  unsigned char *data = random_data(48);
  printf("data:\n");
  printX(data, 48);

  unsigned char *output;
  size_t len = 48;
  output = pad_and_encrypt(data, &len);
  printf("output (%lu):\n", len);
  printX(output, len);
  free(data);
  free(output);


  // To do: generalize print16 - print out a requested number of bytes, 16
  // per line, with fewer perhaps on the final line.

  // for (int i = 0; i < 16; ++i) {
  //   printf("%d ", rand() % 6 + 5);
  // }
  // printf("\n");

  // for (int i = 0; i < 16; ++i) {
  //   unsigned char *pad_str = pad(i, 16);
  //   printf("%2d: ", i);
  //   print16(pad_str);
  //   free(pad_str);
  // }

}

