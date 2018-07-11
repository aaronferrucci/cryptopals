#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "cbc_ecb128.h"
#include "utils.h"

typedef struct t_profile {
  unsigned char *email;
  unsigned char uid;
  unsigned char *role;
} t_profile;

t_profile *profile_for(unsigned char *new_email)
{
  static const char *default_user = "user";
  static unsigned char next_uid = 10;
  // Don't allow overflow.
  if (next_uid == 0)
    return NULL;

  t_profile *prof = (t_profile*)malloc(sizeof(t_profile));
  prof->email = (unsigned char*)malloc((strlen(new_email) + 1) * sizeof(unsigned char));
  unsigned char *p = prof->email;
  // copy new_email into prof->email, omitting illegal bytes
  while (*new_email) {
    if (*new_email != '=' && *new_email != '&')
      *p++ = *new_email;
    new_email++;
  }
  *p = '\0';

  prof->uid = next_uid++;
  prof->role = (unsigned char*)malloc(strlen(default_user) + 1);
  strcpy(prof->role, default_user);
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
  unsigned char *emails[] = {
    "foo@foobar.com",
    "wexilla@prodeunt.com",
    "test=&123@===mon&key.com",
  };
  t_profile *prof;
  unsigned char *prof_str;

  for (int i = 0; i < sizeof(emails) / sizeof(*emails); ++i) {
    prof = profile_for(emails[i]);
    print(prof);

    prof_str = to_str(prof);
    printf("%s\n\n", prof_str);

    delete(&prof);
    free(prof_str);
  }

  return 0;
}

