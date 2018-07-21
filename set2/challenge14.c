#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "cbc_ecb128.h"
#include "utils.h"

static unsigned char unknown_string_base64[] =
  "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
  "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
  "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
  "YnkK";
static unsigned char *unknown_string = NULL;
static size_t unknown_string_len;
static int prefix_len;

static unsigned char key[16] = {'\0',};

// will malloc space for the output. Caller is responsible to free().
unsigned char *pad(size_t len, size_t block_size)
{
  size_t pad_size = block_size - (len % block_size);

  unsigned char *pad = malloc((1 + pad_size) * sizeof(unsigned char));
  unsigned char *pret = pad;
  for (int i = 0; i < pad_size; ++i)
    *pad++ = (unsigned char)pad_size;
  *pad++ = '\0';
  return pret;
}

void init()
{
  // one-time setup
  if (unknown_string == NULL)
    unknown_string = base64_decode(unknown_string_base64, &unknown_string_len);

  while (!key[0])
    random16(key);

  if (prefix_len == 0)
    prefix_len = 1 + rand() % 128;
}

// aes-128-ecb(random_string || input || unknown_string, key)
// mallocs the return string; caller must free
unsigned char *insecure_ecb(unsigned char *input, size_t in_len, size_t *out_len)
{
  unsigned char prefix[prefix_len]; // it's uninitialized, and that's ok

  unsigned char *padding = pad(prefix_len + in_len + unknown_string_len, 16);
  size_t len = prefix_len + in_len + unknown_string_len + strlen(padding);
  unsigned char *plaintext = malloc(len * sizeof(unsigned char));
  unsigned char *output = malloc(len * sizeof(unsigned char));
  *out_len = len;

  for (int i = 0; i < prefix_len; ++i)
    plaintext[i] = prefix[i];
  for (int i = 0; i < in_len; ++i)
    plaintext[i + prefix_len] = input[i];
  for (int i = 0; i < unknown_string_len; ++i)
    plaintext[i + prefix_len + in_len] = unknown_string[i];
  for (int i = 0; i < strlen(padding); ++i)
    plaintext[i + prefix_len + in_len + unknown_string_len] = padding[i];
  free(padding);

  ecb128_encrypt(plaintext, output, len, key);
  free(plaintext);
  return output;
}

void deinit(void)
{
  if (unknown_string) free(unknown_string);
  unknown_string = NULL;
}

int detect_ecb(int block_size)
{
  int ecb_detected = 0;
  assert(sizeof(__uint128_t) == block_size);
  // ecb encrypts identical blocks identically
  // given block size N, repeated characters of length 3 * N
  // will be encrypted as 2 or 3 repeated blocks (3 if the prefix
  // length is an even multiple of block size; 2 otherwise)
  const int blocks = 3;
  unsigned char *text = malloc(blocks * block_size * sizeof(unsigned char));
  for (int i = 0; i < blocks * block_size; ++i)
    text[i] = '*';
  size_t out_len;
  unsigned char *output = insecure_ecb(text, blocks * block_size, &out_len);

  // TO DO: detect <blocks - 1> repeated blocks. That indicates ECB.
  for (int i = block_size; i < out_len; i += block_size) {
    if (EQ_16BYTE(output + i - block_size, output + i)) {
      ecb_detected = 1;
      goto cleanup_and_exit;
    }
  }


cleanup_and_exit:
  free(output);
  free(text);

  return ecb_detected;
}

int find_block_size(void)
{
  int block_size = 0;
  unsigned char *text = malloc(128 * sizeof(unsigned char));
  for (int i = 0; i < 128; ++i)
    text[i] = 'A';
  size_t prev_len = 0;
  for (int i = 1; i < 128; ++i) {
    size_t out_len;
    unsigned char *output = insecure_ecb(text, i, &out_len);
    free(output);
    if (prev_len) {
      if (prev_len != out_len) {
        block_size = (int)(out_len - prev_len);
        break;
      }
    }
    prev_len = out_len;
  }
  free(text);
  return block_size;
}

// Given: an encryption function F which takes an input string, appends its own
// "unknown" string, pads to block size, encrypts with an internal key (same
// key every time) and returns the padded, encrypted output.
//
// By repeatedly calling F with certain inputs, the unknown string can be
// determined.
//
// Method to determine the 1st byte of the unknown string:
// 1. call F("AAAAAAA"), save 1st encrypted block ("probe" block)
// 2. foreach 8-bit value x, call F("AAAAAAA<x>"); if 1st encrypted block
//   matches the probe block, that value of <x> is the 1st byte of "unknown
//   string"
//
// To determine the 2nd byte, if the first byte has been determined as "1":
// 1. call F("AAAAAA") (6 bytes, this time; F will supply its unknown string
// bytes 1 and 2). Save the probe block as before
// 2. foreach 8-bit value x, call F("AAAAAA1<x>"); if 1st encrypted block
//   matches the probe block, that value of <x> is the 2nd byte of "unknown
//   string"
//
// Repeat this process, supplying ever-decreasing input sizes to force F to
// put more unknown bytes into the first block; detect the next unknown byte
// by finding a match with the probe block. Eventually the entire first block
// of the unknown string is revealed.
//
//
// To do: how to find the 2nd (3rd, ... last) blocks of the unknown string??
//
// Assume I know the first 8 bytes: "12345678". How to determine <9>? It needs
// to be the only unknown byte in a block. If I supply a 7-byte block,
// "2345678", then F will construct and encrypt "23456781", "2345678<9>".
// Save that 2nd encrypted block.  Next call F("2345678<x>"), varying <x>
// until it matches the 2nd block. That 2nd block lets me determine <9>.
// Continuing, a 6-byte block results in "34567812", "3456789<A>"...
//
// (I already called F with these blocks previously - if encryption is
// expensive and storage is cheap, would be worthwhile to store all the blocks
// for later lookup.)
//
unsigned char *decrypt(int block_size, size_t *decrypt_len)
{
  // A block of text to encrypt.
  unsigned char *text = NULL;
  unsigned char *encrypted_block = NULL;
  unsigned char *decrypted = NULL;
  size_t out_len;
  int num_blocks = 0;
  *decrypt_len = 0;

  {
    // Calculate how many blocks (bytes) of "unknown string" there are -
    // allocate space for them.
    unsigned char *output = insecure_ecb("", 0, &out_len);
    num_blocks = out_len / block_size;
    decrypted = malloc(out_len * sizeof(unsigned char));
    text = malloc(block_size * sizeof(unsigned char));
    encrypted_block = malloc(block_size * sizeof(unsigned char));
  }

  for (int block = 0; block < num_blocks; ++block) {
    for (int k = 0; k < block_size; ++k) {
      // The 1st k bytes of this block are known; now find the <k+1>th byte.
      // Encrypt with block_size-(k+1) (so the first encrypted block is all
      // known bytes except the last k+1 bytes, which are the 1st k+1 bytes
      // of the unknown string.
      //
      // Here's the tricky part: block 0 is used as a probing block to find the
      // next unknown byte. That unknown byte is in blocks 0, 1, ...
      // Set known values for the text block. For the first block, any value 
      // will do (use 'A'). For subsequent blocks, values from the previous 
      // decrypted block are used.
      // For each decrypted byte, I'll overwrite a new value at the
      // end of the text block.
      // 1st block (8-byte block example):
      //  k  len      text  1st block
      //  0    7   AAAAAAA.  AAAAAAA1
      //  1    6   AAAAAA1.  AAAAAA12
      //  2    5   AAAAA12.  AAAAA123
      //  3    4   AAAA123.  AAAA1234
      //  4    3   AAA1234.  AAA12345
      //  5    2   AA12345.  AA123456
      //  6    1   A123456.  A1234567
      //  7    0   1234567.  12345678
      //       2nd block
      //  k  len      text  2nd block
      //  0    7   2345678.  23456789
      //  1    6   3456789.  3456789A
      //  2    5   456789A.  456789AB
      //  3    4   56789AB.  56789ABC
      //  4    3   6789ABC.  6789ABCD
      //  5    2   789ABCD.  789ABCDE
      //  6    1   89ABCDE.  89ABCDEF
      //  7    0   9ABCDEF.  9ABCDEF0
      //
      //   Method:
      //   1) create 'text' as a function of block, k.
      //      write <block size> - 1 bytes, starting at index 0
      //      text[i] = decrypted[(block - 1) * block_size + k + 1 + i]
      //      (when decrypted index (block - 1) * block_size + k + 1 + i is
      //      negative, use 'A')
      //   2) encrypt, using length <block_size> - 1 - k
      //   3) save encrypted block <block> for later matching
      //   4) repeat over all bytes x:
      //      overwrite the last byte of text with 'x'
      //      encrypt, using size <block size>
      //      check for equality between 1st block and saved block
      //        on a match, save x as the next decrypted byte.

      for (int i = 0; i < block_size - 1; ++i) {
        int index = (block - 1) * block_size + k + 1 + i;
        if (index >= 0)
          text[i] = decrypted[index];
        else
          text[i] = 'A';
      }
      // just for debug clarity: clear the last byte (it'll be set in the loop
      // below).
      text[block_size - 1] = '\0';
      // printf("block: %d; k: %d\n", block, k);
      // print16(text);
      // printf("\n");
      unsigned char *output =
        insecure_ecb(text, block_size - (k+1), &out_len);

      // save a block of the output - it'll be a signature for detecting
      // the next byte of the unknown string
      *(__uint128_t*)encrypted_block =
        *(__uint128_t*)(output + block * block_size);
      free(output);

      int found = 0;
      for (int x = 0; !found && x < 256; ++x) {
        // Each value of 'x' is a candidate for the next decrypted byte.
        text[block_size - 1] = (unsigned char)x;
        // Now encrypt with all <block size> bytes of text, to probe for the
        // value of the first unknown byte.
        unsigned char *output = insecure_ecb(text, block_size, &out_len);
        if (EQ_16BYTE(output, encrypted_block)) {
          decrypted[k + block * block_size] = (unsigned char)x;
          found = 1;
        }
        free(output);
      }
      (*decrypt_len)++;
    }
  }

  free(text);
  free(encrypted_block);

  return decrypted;
}

int main(void)
{
  srand(time(NULL));
  printf("challenge14\n");
  init();

  // 1. Feed identical bytes of your-string to the function 1 at a time ---
  // start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover
  // the block size of the cipher. You know it, but do this step anyway.
  int block_size = find_block_size();
  printf("block size: %d\n", block_size);

  // 2. Detect that the function is using ECB. You already know, but do this
  // step anyway.
  int ecb_detected = detect_ecb(block_size);
  if (!ecb_detected) {
    printf("Error: ECB not detected!\n");
    return -1;
  }
  printf("ECB-%d detected\n", block_size);

  // 3. Knowing the block size, craft an input block that is exactly 1 byte
  // short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think
  // about what the oracle function is going to put in that last byte position.
  // 4. Make a dictionary of every possible last byte by feeding different
  // strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC",
  // remembering the first block of each invocation.
  if (0) {
    size_t decrypt_len = 0;
    unsigned char *decrypted = decrypt(block_size, &decrypt_len);
    for (int i = 0; i < decrypt_len; ++i) {
      printf("%c", decrypted[i]);
    }
    printf("\n");
    free(decrypted);
  }
  // 5. Match the output of the one-byte-short input to one of the entries
  // in your dictionary. You've now discovered the first byte of unknown-string.
  // 6. Repeat for the next byte.

  deinit();

  return 0;
}

