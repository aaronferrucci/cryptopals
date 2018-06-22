
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "utils.h"
#include "cbc_ecb128.h"
#include "c7_data.h"

void main(void)
{
  unsigned char output[16];
  unsigned char output2[16];
  unsigned char key[] = "YELLOW SUBMARINE";
  unsigned char *raw;
  size_t raw_len;
  raw = base64_decode(base64_data, &raw_len);
  printf("%lu bytes of decoded data\n", raw_len);
  print16(raw);
  ecb128_decrypt(raw, output, 16, key);
  free(raw); raw = NULL;
  print16(output);
  ecb128_encrypt(output, output2, 16, key);
  print16(output2);
}

