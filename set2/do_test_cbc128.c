#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "utils.h"
#include "cbc_ecb128.h"
#include "c10_data.h"

#define BLOCKS 3
#define SIZE (16*BLOCKS)
void main(void)
{
  unsigned char output[SIZE];
  unsigned char output2[SIZE];
  unsigned char key[] = "YELLOW SUBMARINE";
  unsigned char iv[16] = {'\0',};
  unsigned char *raw;
  size_t raw_len;
  raw = base64_decode(base64_data, &raw_len);
  printf("%lu bytes of decoded data\n", raw_len);
  for (int i = 0; i < SIZE; i += 16)
    print16(raw + i);

  cbc128_decrypt(raw, output, SIZE, iv, key);
  for (int i = 0; i < SIZE; i += 16)
    print16(output + i);

  cbc128_encrypt(output, output2, SIZE, iv, key);
  for (int i = 0; i < SIZE; i += 16)
    print16(output2 + i);
}

