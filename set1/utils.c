#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <stdio.h>

// The final '==' sequence indicates that the last group contained 
// only one byte, and '=' indicates that it contained two bytes.
static unsigned char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
unsigned char *base64_decode(unsigned char *base64_data)
{
  // convert base64-encoded characters, 4 at a time, into 3 bytes.
  // One or 2 padding characters ('=') are allowed. They occur when the
  // unencoded data length is not a multiple of 3:
  // unencoded length %3    padding
  //                   0     
  //                   1       ==
  //                   2        =
  size_t len = strlen(base64_data); 
  printf("data len: %lu\n", len);
  assert(len % 4 == 0);
  // Each 4 bytes of input create 3 bytes of output - unless there
  // are padding bytes.
  int padding = 0;
  for (int i = 1; i < 3; ++i) {
    unsigned char c = base64_data[len - i];
    if (c == '=') {
      padding++;
    }
  }

  int limit = padding ? len - 4 : len;
  for (int i = 0; i < limit; i += 4) {
    // accumulate 4 complete base64 characters into 3 bytes (24 bits)
    // TO DO: reverse base64[] for fast lookup
  }
  if (padding) {
    // deal the 1 or 2 remaining bytes. Possible to regularize into the 
    // main loop?
  }

  return NULL;
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

