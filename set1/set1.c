#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
void print_bytes(unsigned char *data, int len)
{
  int line1_len = 39;
  for (int i = 0; i < line1_len; ++i) {
    printf(" %c", data[i]);
  }
  printf("\n");
  for (int i = 0; i < line1_len; ++i) {
    printf("%02X", data[i]);
  }
  printf("\n");

  for (int i = line1_len; i < len; ++i) {
    printf(" %c", data[i]);
  }
  printf("\n");
  for (int i = line1_len; i < len; ++i) {
    printf("%02X", data[i]);
  }
  printf("\n");
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

void main(void) 
{
  // 96 nybbles of input, as hex string:
  // that's 48 bytes, or 384 bits, or 64 6-bit numbers.
  char input[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  // I expect the input string to be an even number of nybbles (integer number
  // of bytes)
  assert((strlen(input) % 2) == 0);
  int input_byte_count = strlen(input) / 2;

  unsigned char *bytes = malloc(input_byte_count);
  unsigned char *s = input;
  // Step through the input string, 2 characters at a time, saving the 
  // first 2 characters as a hex number to the bytes array.
  for (int i = 0; i < input_byte_count; ++i) {
    bytes[i] = hex_convert(s);
    s += 2;
  }

  // print_bytes(bytes, input_byte_count);

  // now for base64 encoding. What's the character set?
  unsigned char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  // The lcm of 6 and 8 is 24. Step through the input byte array
  // 3 values at a time, convert those 24 bits to 4 6-bit values,
  // then print each of the 4 as base64.
  //
  // converting to base 64, it'll be simpler if the input bit count is a
  // multiple of 6. The required input meets that condition, so don't bother
  // with a more general solution.
  assert((input_byte_count * 8) % 6 == 0);
  for (int i = 0; i < input_byte_count; i += 3) {
    // collect 3 bytes into a 24-bit value
    int val = 0;
    for (int j = 0; j < 3; ++j) {
      val <<= 8;
      val |= bytes[i + j];
    }

    int mask = ((1 << 6) - 1) << (3 * 6);
    for (int j = 0; j < 4; ++j) {
      int index = (val & mask) >> (3 * 6);
      val <<= 6;
      unsigned b64 = base64[index];
      printf("%c", b64);
    }
    
  }
  printf("\n");

  free(bytes); bytes = NULL;
}

