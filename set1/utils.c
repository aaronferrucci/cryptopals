#include <string.h>
#include <assert.h>
#include <ctype.h>

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

