#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "c7_data.h"

int main(void)
{
  printf("%lu bytes of base64-encoded data\n", strlen(base64_data));
  return 0;
}

