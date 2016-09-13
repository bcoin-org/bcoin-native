#ifndef _BCN_SCRYPT_H
#define _BCN_SCRYPT_H

#include <stdint.h>
#include <stdlib.h>

bool
bcn_scrypt(
  const char *pass,
  const unsigned int passlen,
  const unsigned char *salt,
  size_t saltlen,
  unsigned long long N,
  unsigned long long r,
  unsigned long long p,
  unsigned char *key,
  size_t keylen
);

#endif
