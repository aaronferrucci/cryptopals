#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include "utils.h"

float score_printability(unsigned char *data, int len) {
  int pcount = 0;
  for (int i = 0; i < len; ++i) {
    if (isprint(data[i]))
      pcount++;
  }

  return (float)pcount / len;
}

float score_etaoin(unsigned char *data, int len) {
  // Simple: ratio of 'e' and 'E' to byte count
  int ecount = 0;
  for (int i = 0; i < len; ++i) {
    if (tolower(data[i]) == 'e')
      ecount++;
  }

  return (float)ecount / len;
}

void decode(unsigned char *data, unsigned char key, int len)
{
  for (int i = 0; i < len; ++i) {
    data[i] ^= key;
  }
}

int main(void) 
{
  // Input, "encrypted" by XOR with a single character
  char input[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

  // I expect the input string to be an even number of nybbles (integer number
  // of bytes)
  assert((strlen(input) % 2) == 0);
  int input_byte_count = strlen(input) / 2;

  unsigned char *raw = malloc(sizeof(char) * input_byte_count);
  unsigned char *copy = malloc(sizeof(char) * input_byte_count);
  decode_hex_string(input, raw, input_byte_count);

  for (int key = 0; key < 256; ++key) {
    for (int i = 0; i < input_byte_count; ++i) {
      copy[i] = raw[i];
    }
    decode(copy, key, input_byte_count);
    float score = 
      score_printability(copy, input_byte_count) +
      score_etaoin(copy, input_byte_count);

    printf("%g key: %c (0x%X);\n", score, isprint(key) ? key : '*', key);
  }

  free(raw); raw = NULL;
  return 0;
}

