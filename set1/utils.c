#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "utils.h"

// The final '==' sequence indicates that the last group contained 
// only one byte, and '=' indicates that it contained two bytes.
static unsigned char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static unsigned char reverse_base64[256];

static unsigned char decode_base64_char(unsigned char c)
{
  static int initialized = 0;
  if (!initialized) {
    for (int i = 0; i < sizeof(reverse_base64) / sizeof(*reverse_base64); ++i)
      reverse_base64[i] = -1; // invalid

    unsigned char *const b64_ptr = base64;
    for (int i = 0; i < strlen(base64); ++i) {
      reverse_base64[base64[i]] = i;
    }

    initialized = 1;
  }
  unsigned char decoded = reverse_base64[c];
  assert(decoded != -1);
  return decoded;
}

// Will allocate memory; caller is responsible for calling free().
unsigned char *base64_decode(unsigned char *const base64_data, size_t *output_len)
{
  // convert base64-encoded characters, 4 at a time, into 3 bytes.
  // One or 2 padding characters ('=') are allowed. They occur when the
  // unencoded data length is not a multiple of 3:
  // unencoded length mod 3    padding
  //                      0
  //                      1        ==
  //                      2         =
  *output_len = 0;
  size_t input_len = strlen(base64_data); 
  assert(input_len % 4 == 0);
  // Each 4 bytes of input create 3 bytes of output - unless there
  // are padding bytes. If there are padding bytes, think of the 
  // input as split into "full-size" and "ragged" regions.
  int padding = 0;
  for (int i = 1; i < 3; ++i) {
    unsigned char c = base64_data[input_len - i];
    if (c == '=')
      padding++;
  }

  *output_len = (input_len * 3 / 4) - padding;
  unsigned char *output_data =
    (unsigned char*)calloc(sizeof(char), *output_len);
  int output_data_index = 0;
  int full_size_limit = padding ? input_len - 4 : input_len;
  for (int i = 0; i < input_len; i += 4) {
    unsigned int bits24 = 0;
    unsigned int mask = 0xFF;
    unsigned int shift = 0;
    int in_fullsize_region = i < full_size_limit;
    // accumulate 4 (or fewer) complete base64 characters into 3 bytes (24 bits)
    int input_char_limit = in_fullsize_region ? 4 : 4 - padding;
    for (int j = 0; j < input_char_limit; ++j)  {
      unsigned char bits6 = decode_base64_char(base64_data[i + j]);
      bits24 = (bits24 << 6) | bits6;
      mask <<= 6;
      shift += 6;
    }

    // extract the 3 (or fewer) output bytes.
    int output_char_limit = in_fullsize_region ? 3 : 3 - padding;
    for (int j = 0; j < output_char_limit; ++j) {
      bits24 <<= 8;
      output_data[output_data_index++] = (bits24 & mask) >> shift;
    }
  }

  return output_data;
}

size_t count_bits(unsigned char c)
{
  size_t count = 0;

  while (c) {
    count += c & 1;
    c >>= 1;
  }
  return count;
}

size_t hamming(char *s1, char *s2, size_t len)
{
  size_t distance = 0;

  for (int i = 0; i < len; ++i) {
    distance += count_bits(*s1 ^ *s2);
    s1++;
    s2++;
  }

  return distance;
}

// Convert the first two characters in the input string from hex to a raw
// value.
unsigned char nibble_convert(char c)
{
  unsigned char val;
  c = tolower(c);
  if (c >= 'a' && c <= 'f')
    val = c - 'a' + 10;
  else if (c >= '0' && c <= '9')
    val = c - '0';
  else {
    // error
    val = (unsigned char)-1;
  }

  assert(val >= 0 && val < 0x10);
  return val;
}

unsigned char hex_convert(char *s) 
{
  unsigned char val = 0;
  assert(*s);
  unsigned char upper = nibble_convert(*s);
  unsigned char lower = nibble_convert(*(s + 1));
  val = (upper << 4) | lower;

  return val;
}

// s: input string, hex encoded
// bytes: an array large enough to hold the decoded bytes
// byte_count: number of resulting bytes
void decode_hex_string(char *s, unsigned char *bytes, int byte_count)
{
  // Step through the input string, 2 characters at a time, saving the 
  // first 2 characters as a hex number to the bytes array.
  assert(strlen(s) == 2 * byte_count);
  for (int i = 0; i < byte_count; ++i, s += 2)
    bytes[i] = hex_convert(s);
}
// I found these letter frequencies here:
//   http://norvig.com/mayzner.html
static t_letter_frequency etaoin[] = {
  ' ', 0.200, 0,
  'e', 0.125, 0,
  't', 0.093, 0,
  'a', 0.080, 0,
  'o', 0.076, 0,
  'i', 0.076, 0,
  'n', 0.072, 0,
};

static float bell(float x, float mu, float sigma)
{
  float exponent = -(x - mu) * (x - mu) / (2 * sigma * sigma);
  return exp(exponent) / sigma;
}

// Output: larger numbers for better matches to the given etaoin frequencies
// lower numbers for less-perfect match. (It would be nice to normalize this
// to a range [0, 1].)
float score_etaoin(unsigned char *data, int start, int stride, int len)
{
  float score = 0.;
  for (int i = 0; i < sizeof(etaoin) / sizeof(*etaoin); ++i) {
    int count = 0;
    for (int j = start; j < len; j += stride) {
      if (tolower(data[j]) == etaoin[i].letter)
        count++;
    }
    float delta = bell((float)count / len, etaoin[i].frequency, 0.125);
    score += delta;
  }

  return score;
}

void xor_decode(unsigned char *data, unsigned char key, int len)
{
  for (int i = 0; i < len; ++i) {
    data[i] ^= key;
  }
}

void repeating_xor_decode(unsigned char *data, unsigned char *key, int len)
{
  unsigned char *cur_key = key;
  for (int i = 0; i < len; ++i) {
    data[i] ^= *cur_key;
    cur_key++;
    if (!*cur_key)
      cur_key = key;
  }
}

unsigned char max_xor_key(unsigned char *data, int start, int stride, int len)
{
  float max_score = 0;
  unsigned char max_key;
  unsigned char *copy = malloc(sizeof(unsigned char) * len);
  for (int key = 0; key < 256; ++key) {
    for (int i = 0; i < len; ++i) {
      copy[i] = data[i];
    }
    xor_decode(copy, key, len);
    float score = score_etaoin(copy, start, stride, len);
    // printf("%g: key: %c (0x%02X)\n", score, isprint(key) ? key : '*', key);

    if (score > max_score) {
      max_score = score;
      max_key = key;
    }
  }

  free(copy); copy = NULL;

  return max_key;
}

void printLine(unsigned char *data, size_t len)
{
  for (int i = 0; i < len; ++i) {
    printf("%02X ", data[i]);
  }
  for (int i = len; i < 16; ++i) {
    printf("   ");
  }
  printf("  ");
  for (int i = 0; i < len; ++i) {
    printf("%c", isprint(data[i]) ? data[i] : '.');
  }
  for (int i = len; i < 16; ++i) {
    printf(" ");
  }
  printf("\n");
}

void printX(unsigned char *data, size_t len)
{
  for (int i = 0; i < len; i += 16) {
    printLine(data + i, len - i > 16 ? 16 : len - i);
  }
}

void print16(unsigned char *data)
{
  printLine(data, 16);
}

