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

  unsigned char *raw = base64_decode(base64_data);

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
  return 0;
}

