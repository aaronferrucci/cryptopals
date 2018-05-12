#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

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
  // unencoded length %3    padding
  //                   0     
  //                   1       ==
  //                   2        =
  *output_len = 0;
  size_t input_len = strlen(base64_data); 
  assert(input_len % 4 == 0);
  // Each 4 bytes of input create 3 bytes of output - unless there
  // are padding bytes.
  int padding = 0;
  for (int i = 1; i < 3; ++i) {
    unsigned char c = base64_data[input_len - i];
    if (c == '=') {
      padding++;
    }
  }

  *output_len = input_len * 3 / 4;
  *output_len -= padding;
  unsigned char *output_data =
    (unsigned char*)calloc(sizeof(char), *output_len);
  int output_data_index = 0;
  int limit = padding ? input_len - 4 : input_len;
  for (int i = 0; i < limit; i += 4) {
    unsigned int bits24 = 0;
    unsigned int mask = 0xFF;
    unsigned int shift = 0;
    // accumulate 4 complete base64 characters into 3 bytes (24 bits)
    for (int j = 0; j < 4; ++j)  {
      unsigned char bits6 = decode_base64_char(base64_data[i + j]);
      bits24 = (bits24 << 6) | bits6;
      mask <<= 6;
      shift += 6;
    }

    for (int j = 0; j < 3; ++j) {
      bits24 <<= 8;
      output_data[output_data_index++] = (bits24 & mask) >> shift;
    }
  }

  if (padding) {
    // deal the 1 or 2 remaining output bytes. Possible to regularize into the 
    // main loop?
    // padding  input bytes output bytes
    //       1            3            2
    //       2            2            1
    unsigned int bits24 = 0;
    unsigned int mask = 0xFF;
    unsigned int shift = 0;
    for (int j = 0; j < 4 - padding; ++j)  {
      unsigned char bits6 = decode_base64_char(base64_data[limit + j]);
      bits24 = (bits24 << 6) | bits6;
      mask <<= 6;
      shift += 6;
    }
    for (int j = 0; j < 3 - padding; ++j) {
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

size_t hamming(char *s1, char *s2)
{
  assert(strlen(s1) == strlen(s2));
  size_t distance = 0;

  while (*s1) {
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

