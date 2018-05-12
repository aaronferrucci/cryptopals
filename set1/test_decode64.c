#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

int main(int argc, char **argv)
{
  int return_code = 0;
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <base64 encoded> <expected decoded>\n", *argv);
    return -1;
  }

  unsigned char *encoded = argv[1];
  unsigned char *expect_decoded = argv[2];
  unsigned char *decoded;
  size_t len;
  decoded = base64_decode(encoded, &len);

  if (!strcmp(decoded, expect_decoded)) {
    printf("Test passed: '%s' decodes to '%s'\n", encoded, decoded);
  } else {
    fprintf(stderr, "Test failed: decode '%s':\n  actual:   '%s'\n  expected: '%s'\n",
      encoded, decoded, expect_decoded);
    return_code = -1;
  }
  
  free(decoded);
  return return_code;
}

