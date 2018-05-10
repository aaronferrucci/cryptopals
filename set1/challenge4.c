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

typedef struct {
  float printability;
  float etaoin;
  float spacey;
} t_score;

// return the score for the best key on the given input
// that best key is assigned to *best_key
float get_best_key(char *input, unsigned char *best_key)
{
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
    t_score score;

    for (int i = 0; i < input_byte_count; ++i) {
      copy[i] = raw[i];
    }
    decode(copy, key, input_byte_count);
    score.printability = score_printability(copy, input_byte_count);
    score.etaoin = score_etaoin(copy, input_byte_count);
    score.spacey = score_spacey(copy, input_byte_count);
    float sum = score.printability + score.etaoin + score.spacey;

    if (sum > max_score) {
      max_score = sum;
      max_key = key;
    }
  }

  free(raw); raw = NULL;
  free(copy); copy = NULL;

  *best_key = max_key;
  return max_score;
}

void decrypt_and_print(char *input, unsigned char key)
{
  assert((strlen(input) % 2) == 0);
  int input_byte_count = strlen(input) / 2;
  unsigned char *raw = malloc(sizeof(char) * input_byte_count);
  decode_hex_string(input, raw, input_byte_count);

  decode(raw, key, input_byte_count);

  for (int i = 0; i < input_byte_count; ++i) {
    printf("%c", raw[i]);
  }
  printf("\n");
  free(raw); raw = NULL;
}


#include "c4_data.h"
int main(void) 
{
  unsigned char best_key;
  float max_score = -1;;
  int best_index;
  for (int i = 0; i < sizeof(data) / sizeof(*data); ++i) {
    float score;
    unsigned char key;
    score = get_best_key(data[i], &key);
    if (score > max_score) {
      max_score = score;
      best_index = i;
      best_key = key;
    }
  }
  printf("max_score, best_index, best_key\n");
  printf("%g, %d, %c\n", max_score, best_index, best_key);

  decrypt_and_print(data[best_index], best_key);
  return 0;
}

