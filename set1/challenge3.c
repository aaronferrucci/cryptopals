#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include "utils.h"

int main(void) 
{

  // Input, "encrypted" by XOR with a single character
  char input[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

  // I expect the input string to be an even number of nybbles (integer number
  // of bytes)
  assert((strlen(input) % 2) == 0);
  int input_byte_count = strlen(input) / 2;

  unsigned char *raw = malloc(sizeof(char) * input_byte_count);
  decode_hex_string(input, raw, input_byte_count);

  unsigned char max_key;
  max_key = max_xor_key(raw, 0, 1, input_byte_count);
  unsigned char *copy = malloc(sizeof(char) * input_byte_count);

  // p-hacking, yes, but just print the max-score plaintext.
  for (int i = 0; i < input_byte_count; ++i) {
    copy[i] = raw[i];
  }
  xor_decode(copy, max_key, input_byte_count);

  for (int i = 0; i < input_byte_count; ++i) {
    printf("%c", copy[i]);
  }
  printf("\n");

  free(raw); raw = NULL;
  free(copy); copy = NULL;
  return 0;
}

