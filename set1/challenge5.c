#include <stdio.h>
#include <assert.h>
#include <string.h>

int main(void) 
{
  unsigned char input[] =
  "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
  unsigned char key[] = "ICE";

  for (int i = 0; i < strlen(input); ++i) {
    printf("%02x", input[i] ^ key[i % strlen(key)]);
  }
  printf("\n");
  return 0;
}

