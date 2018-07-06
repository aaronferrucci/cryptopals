#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "c8_data.h"
#include "utils.h"

#define ASCII_LEN 320
#define RAW_LEN 160
#define BLOCK_SIZE 16
#define BLOCKS_PER_LINE ((RAW_LEN) / (BLOCK_SIZE))
#define HASH_EMPTY_VALUE ((__uint128_t)-1)

// Find in hash, or put in hash. Return index.
int get(__uint128_t *hash, __uint128_t data, size_t len)
{
  // I'm using 0 as the "unallocated" value. Make sure that's ok.
  assert(data != HASH_EMPTY_VALUE);
  int i = 0;
  for (i = 0; i < BLOCKS_PER_LINE; ++i) {
    if (hash[i] == HASH_EMPTY_VALUE) {
      // reached end of allocated space
      hash[i] = data;
      break;
    } else if (hash[i] == data) {
      break;
    }
  }
  assert(i < BLOCKS_PER_LINE);
  return i;
}

int main(void)
{
  unsigned char raw[RAW_LEN];

  // each line has at most BLOCKS_PER_LINE unique 16-byte blocks
  __uint128_t hash[BLOCKS_PER_LINE] = {0,};

  assert(ASCII_LEN == 2 * RAW_LEN);
  assert(BLOCKS_PER_LINE * BLOCK_SIZE == RAW_LEN);
  assert(sizeof(__uint128_t) == BLOCK_SIZE);

  printf("found %lu lines of ciphertext\n", sizeof(crypt_data) / sizeof(*crypt_data));
  for (int i = 0; i < sizeof(crypt_data) / sizeof(*crypt_data); ++i) {
    // n^2 search for duplicate 16-char blocks in this string
    assert(strlen(crypt_data[i]) == ASCII_LEN);
    decode_hex_string(crypt_data[i], raw, RAW_LEN);

    // 160 bytes, 10 16-byte "blocks"
    // Clear the hash.
    for (int j = 0; j < BLOCKS_PER_LINE; ++j) {
      hash[j] = -1;
    }

    // For each block in the data...
    int all_unique = 1;
    // printf("%3d: ", i);
    for (int j = 0; j < BLOCKS_PER_LINE; ++j) {
      // Find this block in the hash, or save it in the hash
      int hash_index = get(hash, *(__uint128_t*)(raw + BLOCK_SIZE * j), BLOCK_SIZE);
      // printf("%u ", hash_index);
      if (j != hash_index) {
        all_unique = 0;
      }
    }
    // printf("%c\n", all_unique ? ' ' : '*');
    if (!all_unique) {
      printf("\nciphertext element %d has non-unique blocks:\n", i);
      // oops, endianness. Below works for a big-endian processor... I guess
      // for (int j = 0; j < BLOCKS_PER_LINE; ++j) {
      //   printf("  %lX\n", *(__uint128_t*)(raw + BLOCK_SIZE * j));
      // }

      // To the surprise of this little-endian processor, the MSbyte of each
      // 16-byte block occurs first (in left to right order).
      for (int j = 0; j < RAW_LEN; ++j) {
        printf("%s%02x%s", (j % BLOCK_SIZE) == 0 ? "  " : "", raw[j], (j % BLOCK_SIZE) == BLOCK_SIZE - 1 ? "\n" : "");
      }
    }
  }

  return 0;
}

