/*
Some content-encryption algorithms assume the
input length is a multiple of k octets, where k > 1, and
let the application define a method for handling inputs
whose lengths are not a multiple of k octets. For such
algorithms, the method shall be to pad the input at the
trailing end with k - (l mod k) octets all having value k -
(l mod k), where l is the length of the input. In other
words, the input is padded at the trailing end with one of
the following strings:

        01 -- if l mod k = k-1
        02 02 -- if l mod k = k-2
                    .
                    .
                    .
      k k ... k k -- if l mod k = 0

The padding can be removed unambiguously since all input is
padded and no padding string is a suffix of another. This
padding method is well-defined if and only if k < 256;
methods for larger k are an open issue for further study.
*/
/*
Implement PKCS#7 padding
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

"YELLOW SUBMARINE"
... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// will malloc space for the output. Caller is responsible to free().
unsigned char *pkcs_n7_pad(unsigned char *s, size_t block_size)
{
  size_t len = strlen(s);
  size_t pad_size = block_size - (len % block_size);

  unsigned char *padded = malloc((1 + len + pad_size) * sizeof(unsigned char));
  unsigned char *pret = padded;
  while (*s)
    *padded++ = *s++;
  for (int i = 0; i < pad_size; ++i)
    *padded++ = (unsigned char)pad_size;

  *padded = '\0';
  return pret;
}

void main(void)
{
  unsigned char *test = "YELLOW SUBMARINE";
  unsigned char *padded = pkcs_n7_pad(test, 20);
  for (int i = 0; i < strlen(padded); ++i) {
    if (isprint(padded[i]))
      printf("%c", padded[i]);
    else
      printf("\\x%02X", padded[i]);
  }
  printf("\n");
  free(padded);
}

