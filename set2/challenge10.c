#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "cbc_ecb128.h"
#include "c10_data.h"
#include "utils.h"

void print16(unsigned char *data)
{
  for (int i = 0; i < 16; ++i) {
    printf("%02X ", data[i]);
  }
  printf("  ");
  for (int i = 0; i < 16; ++i) {
    printf("%c", isprint(data[i]) ? data[i] : '.');
  }
  printf("\n");
}

void main(void)
{
  unsigned char key[] = "YELLOW SUBMARINE";
  unsigned char iv[16] = {'\0',};

  size_t data_size;
  unsigned char *data = base64_decode(base64_data, &data_size);
  printf("input length: %lu\n", data_size);

  print16(key);
  unsigned char *output = (unsigned char*)malloc(data_size * sizeof(unsigned char));

  cbc128_decrypt(data, output, data_size, iv, key);

  for (int i = 0; i < data_size; i += 16) {
    print16(output + i);
  }
}

