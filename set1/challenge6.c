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
  unsigned char buf_1st[MAX_KEYSIZE];
  unsigned char buf_2nd[MAX_KEYSIZE];
  printf("%s\t%s\t%s\n", "norm distance", "keysize", "hamming distance");
  for (int keysize = MIN_KEYSIZE; keysize < MAX_KEYSIZE; ++keysize) {
    // 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the 
    // second KEYSIZE worth of bytes, and find the edit distance between 
    // them. Normalize this result by dividing by KEYSIZE.
    strncpy(buf_1st, raw, keysize);
    buf_1st[keysize] = '\0';
    strncpy(buf_2nd, raw + keysize, keysize);
    buf_2nd[keysize] = '\0';
    size_t dist = hamming(buf_1st, buf_2nd, keysize);
    printf("%g\t%lu\t%d\n", (float)dist / keysize, keysize, dist);
    
    // 4. The KEYSIZE with the smallest normalized edit distance is probably 
    // the key. You could proceed perhaps with the smallest 2-3 KEYSIZE 
    // values. Or take 4 KEYSIZE blocks instead of 2 and average the 
    // distances.
  }

  free(raw);
  return 0;
}

