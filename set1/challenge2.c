#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include "utils.h"

void main(void) 
{
  // inputs: 2 strings (hex values)
  // XOR together, print output.
  char input1[] = "1c0111001f010100061a024b53535009181c";
  char input2[] = "686974207468652062756c6c277320657965";

  // I expect the input string to be an even number of nybbles (integer number
  // of bytes)
  assert((strlen(input1) % 2) == 0);
  assert(strlen(input1) == strlen(input2));
  int input_byte_count = strlen(input1) / 2;

  unsigned char *raw1 = malloc(sizeof(char) * input_byte_count);
  unsigned char *raw2 = malloc(sizeof(char) * input_byte_count);
  decode_hex_string(input1, raw1, input_byte_count);
  decode_hex_string(input2, raw2, input_byte_count);

  for (int i = 0; i < input_byte_count; ++i) {
    printf("%02x", raw1[i] ^ raw2[i]);
  }
  printf("\n");

  free(raw1); raw1 = NULL;
  free(raw2); raw2 = NULL;
}

