#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include "utils.h"
#include "c6_data.h"

void sanity(void)
{
  assert(37 == hamming("this is a test", "wokka wokka!!!"));
}

int main(void) 
{
  sanity();

  unsigned char test[] =
    "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

  size_t len;
  unsigned char *decode = base64_decode(test, &len);
  for (int i = 0; i < len; ++i) {
    printf("%02X\n", decode[i]);
  }
  printf("\n");
  for (int i = 0; i < len; ++i) {
    printf("%c", decode[i]);
  }
  printf("\n");

//  unsigned char *raw = base64_decode(base64_data, &len);

  
  // 1. Let KEYSIZE be the guessed length of the key; try values from 2 to 
  // (say) 40.
  for (int keysize = 2; keysize < 40; ++keysize) {
    // 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the 
    // second KEYSIZE worth of bytes, and find the edit distance between 
    // them. Normalize this result by dividing by KEYSIZE.
    //
    
    // 4. The KEYSIZE with the smallest normalized edit distance is probably 
    // the key. You could proceed perhaps with the smallest 2-3 KEYSIZE 
    // values. Or take 4 KEYSIZE blocks instead of 2 and average the 
    // distances.
  }
  free(decode);
  // free(raw);
  return 0;
}

