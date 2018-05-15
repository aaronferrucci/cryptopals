#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include "utils.h"

// Look at all these score_* functions. They're pretty similar;
// could do a generic function that takes a comparison function pointer.
float score_printability(unsigned char *data, int len) {
  int pcount = 0;
  for (int i = 0; i < len; ++i) {
    if (isprint(data[i]))
      pcount++;
  }

  return (float)pcount / len;
}

float score_spacey(unsigned char *data, int len) {
  // Simple: ratio of ' ' to all
  int scount = 0;
  for (int i = 0; i < len; ++i) {
    if (tolower(data[i]) == ' ')
      scount++;
  }

  return (float)scount / len;
}

void decode(unsigned char *data, unsigned char key, int len)
{
  for (int i = 0; i < len; ++i) {
    data[i] ^= key;
  }
}

typedef struct {
  float printability;
  float etaoin;
  float spacey;
} t_score;

int main(void) 
{
  t_score scores[256] = { {0,},};

  // Input, "encrypted" by XOR with a single character
  char input[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

  // I expect the input string to be an even number of nybbles (integer number
  // of bytes)
  assert((strlen(input) % 2) == 0);
  int input_byte_count = strlen(input) / 2;

  unsigned char *raw = malloc(sizeof(char) * input_byte_count);
  unsigned char *copy = malloc(sizeof(char) * input_byte_count);
  decode_hex_string(input, raw, input_byte_count);

  float max_score = 0;
  unsigned char max_key;
  for (int key = 0; key < 256; ++key) {
    for (int i = 0; i < input_byte_count; ++i) {
      copy[i] = raw[i];
    }
    decode(copy, key, input_byte_count);
    // scores[key].printability = score_printability(copy, input_byte_count);
    // scores[key].spacey = score_spacey(copy, input_byte_count);
    // float sum = scores[key].printability + scores[key].etaoin + scores[key].spacey;
    scores[key].etaoin = score_etaoin(copy, input_byte_count);
    float score = scores[key].etaoin;
    // printf("%g: key: %c (0x%02X)\n", score, isprint(key) ? key : '*', key);

    if (score > max_score) {
      max_score = score;
      max_key = key;
    }
  }

  // p-hacking, yes, but just print the max-score plaintext.
  for (int i = 0; i < input_byte_count; ++i) {
    copy[i] = raw[i];
  }
  decode(copy, max_key, input_byte_count);

  for (int i = 0; i < input_byte_count; ++i) {
    printf("%c", copy[i]);
  }
  printf("\n");

  free(raw); raw = NULL;
  return 0;
}

