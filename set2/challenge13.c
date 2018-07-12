#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "cbc_ecb128.h"
#include "utils.h"

static unsigned char key[16] = {'\0',};

// will malloc space for the output. Caller is responsible to free().
unsigned char *pad(size_t len, size_t block_size)
{
  size_t pad_size = block_size - (len % block_size);

  unsigned char *pad = malloc((1 + pad_size) * sizeof(unsigned char));
  unsigned char *pret = pad;
  for (int i = 0; i < pad_size; ++i)
    *pad++ = (unsigned char)pad_size;
  *pad++ = '\0';
  return pret;
}

void init()
{
  // one-time setup
  while (!key[0]) {
    random16(key);
  }
}

// aes-128-ecb(input, key)
// mallocs the return string; caller must free
unsigned char *ecb_encrypt(unsigned char *input, size_t in_len, size_t *out_len)
{
  unsigned char *padding = pad(in_len, 16);
  size_t len = in_len + strlen(padding);
  unsigned char *plaintext = malloc(len * sizeof(unsigned char));
  unsigned char *output = malloc(len * sizeof(unsigned char));
  *out_len = len;

  for (int i = 0; i < in_len; ++i)
    plaintext[i] = input[i];
  for (int i = 0; i < strlen(padding); ++i)
    plaintext[i + in_len] = padding[i];
  free(padding);

  printf("padded plaintext:\n");
  printX(plaintext, len);
  printf("\n");
  ecb128_encrypt(plaintext, output, len, key);
  free(plaintext);
  return output;
}

unsigned char *ecb_decrypt(unsigned char *input, size_t crypt_len)
{
  unsigned char *output = malloc(crypt_len * sizeof(unsigned char));

  ecb128_decrypt(input, output, crypt_len, key);
  unsigned char last_pad = output[crypt_len - 1];
  assert(last_pad > 0 && last_pad <= 16);
  unsigned char *pfirst_pad = output + crypt_len - last_pad;
  *pfirst_pad = '\0';
  return output;
}

void deinit(void)
{
}

typedef struct t_profile {
  unsigned char *email;
  unsigned char uid;
  unsigned char *role;
} t_profile;

t_profile *new_profile(unsigned char *email, int uid, const unsigned char *role)
{
  t_profile *prof = (t_profile*)malloc(sizeof(t_profile));
  prof->email = (unsigned char*)malloc((strlen(email) + 1) * sizeof(unsigned char));
  unsigned char *p = prof->email;
  // copy new_email into prof->email, omitting illegal bytes
  while (*email) {
    if (*email != '=' && *email != '&')
      *p++ = *email;
    email++;
  }
  *p = '\0';

  prof->uid = uid;
  prof->role = (unsigned char*)malloc(strlen(role) + 1);
  strcpy(prof->role, role);
  return prof;
}

t_profile *parse(unsigned char *encoded)
{
  // These arrays are too big! That's ok.
  unsigned char *email = malloc((strlen(encoded) + 1) * sizeof(unsigned char));
  int uid;
  unsigned char *role = malloc((strlen(encoded) + 1) * sizeof(unsigned char));

  unsigned char *token = strtok(encoded, "&=");
  unsigned char *prev_token = NULL;
  while (token) {
    if (prev_token) {
      if (!strcmp(prev_token, "email")) {
        strcpy(email, token);
      } else if (!strcmp(prev_token, "uid")) {
        uid = atoi(token);
      } else if (!strcmp(prev_token, "role")) {
        strcpy(role, token);
      }
    }
    prev_token = token;
    token = strtok(NULL, "&=");
  }

  t_profile *prof = new_profile(email, uid, role);
  free(email);
  free(role);
  return prof;
}

t_profile *profile_for(unsigned char *new_email)
{
  static const char *default_role = "user";
  static unsigned char next_uid = 10;
  // Don't allow overflow.
  if (next_uid == 0)
    return NULL;

  t_profile *prof = new_profile(new_email, next_uid++, default_role);
  return prof;
}

void print(t_profile *prof)
{
  printf("email: '%s'\n", prof->email);
  printf("uid: %u\n", prof->uid);
  printf("role: '%s'\n", prof->role);
}

unsigned char *to_str(t_profile *profile)
{
  size_t uid_len = profile->uid <  10 ? 1 :
                   profile->uid < 100 ? 2 :
                   3;
  size_t len =
    strlen("email=") + strlen(profile->email) + 1 +
    strlen("uid=") + uid_len + 1 +
    strlen("role=") + strlen(profile->role) +
    1;
  unsigned char *str = malloc(len * sizeof(unsigned char));

  sprintf(str, "email=%s&uid=%d&role=%s", profile->email, profile->uid, profile->role);

  return str;
}

void delete(t_profile **pprof)
{
  free((*pprof)->email);
  free((*pprof)->role);
  free(*pprof);
  pprof = NULL;
}

int main(void)
{
  init();
  unsigned char *emails[] = {
    "a123456@b.com",
  };
  t_profile *prof;
  unsigned char *prof_str;

  for (int i = 0; i < sizeof(emails) / sizeof(*emails); ++i) {
    prof = profile_for(emails[i]);
    print(prof);

    prof_str = to_str(prof);
    printf("%s\n\n", prof_str);

    size_t out_len;
    unsigned char *crypt = ecb_encrypt(prof_str, strlen(prof_str), &out_len);
    printf("encrypted:\n");
    printX(crypt, out_len);
    printf("\n");

    unsigned char *decrypt = ecb_decrypt(crypt, out_len);
    printf("decrypted, unpadded:\n");
    printf("%s\n\n", decrypt);

    printf("parsed:\n");
    t_profile *prof2 = parse(decrypt);
    print(prof2);
    printf("\n");

    delete(&prof);
    delete(&prof2);
    free(prof_str);
    free(crypt);
    free(decrypt);
  }

  deinit();
  return 0;
}

