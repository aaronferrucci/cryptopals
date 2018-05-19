#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "c8_data.h"
#include "utils.h"

int main(void)
{
  unsigned char raw[160];

  printf("found %lu lines of ciphertext\n", sizeof(crypt_data) / sizeof(*crypt_data));
  for (int i = 0; i < sizeof(crypt_data) / sizeof(*crypt_data); ++i) {
    // painful n^2 search for duplicate 16-char blocks in this string
    assert(strlen(crypt_data[i]) == 320);
    decode_hex_string(crypt_data[i], raw, 160);

    printf("%c%c <-> %02x\n", crypt_data[i][0], crypt_data[i][1], raw[0]);
  }
}

