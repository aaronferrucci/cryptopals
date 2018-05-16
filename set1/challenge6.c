#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include "utils.h"
#include "c6_data.h"

void sanity(void)
{
  unsigned char s1[] = "this is a test";
  unsigned char s2[] = "wokka wokka!!!";
  assert(strlen(s1) == strlen(s2));
  assert(37 == hamming(s1, s2, strlen(s1)));
}

#define MIN_KEYSIZE 2 
#define MAX_KEYSIZE 40
int main(void) 
{
  sanity();

  size_t len;
  unsigned char *raw = base64_decode(base64_data, &len);
  printf("base64-encoded input of size %lu decodes to %lu bytes\n", strlen(base64_data), len);
  
  // 1. Let KEYSIZE be the guessed length of the key; try values from 2 to 
  // (say) 40.
  printf("%s\t%s\t%s\n", "norm distance", "keysize", "hamming distance");
  for (int keysize = MIN_KEYSIZE; keysize <= MAX_KEYSIZE; ++keysize) {
    // 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the 
    // second KEYSIZE worth of bytes, and find the edit distance between 
    // them. Normalize this result by dividing by KEYSIZE.
    size_t dist = 0;
    int diffs;
    for (diffs = 0; diffs < 3; ++diffs) {
      dist += hamming(raw + diffs * keysize, raw + (diffs + 1) * keysize, keysize);
    }
    // printf("%g\t\t%d\t%lu\n", (float)dist / diffs / keysize, keysize, dist);
    
    // 4. The KEYSIZE with the smallest normalized edit distance is probably 
    // the key. You could proceed perhaps with the smallest 2-3 KEYSIZE 
    // values. Or take 4 KEYSIZE blocks instead of 2 and average the 
    // distances.
  }
  // Now that you probably know the KEYSIZE: break the ciphertext into blocks 
  // of KEYSIZE length.
  // Now transpose the blocks: make a block that is the first byte of every 
  // block, and a block that is the second byte of every block, and so on.
  // implementation notes:
  // create KEYSIZE arrays, each of length ceil(input data size) / KEYSIZE
  // initialize array "i" with input data values i, 2*i, 3*i, ...
  //   note that allocation of these arrays isn't actually required - all I'm
  //   doing is stepping through the input data in a different linear order.
  //

  int keysize = 29;
  printf("keysize: %d\n", keysize);
  unsigned char *key = malloc(keysize + 1);
  int i;
  for (i = 0; i < keysize; ++i) {
    key[i] = max_xor_key(raw, i, keysize, len);
  }
  key[i] = '\0';
  printf("key: '%s'\n", key);
  repeating_xor_decode(raw, key, len); 
  printf("decoded: '%s'\n", raw);

  free(key);
  free(raw);
  return 0;
}

