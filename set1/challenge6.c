#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include "utils.h"
#include "c6_data.h"

void sanity(void)
{
  assert(37 == hamming("this is a test", "wokka wokka!!!"));
}

int main(void) 
{
  sanity();

  return 0;
}

