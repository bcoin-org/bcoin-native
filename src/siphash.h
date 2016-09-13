#ifndef _BCN_SIPHASH_H
#define _BCN_SIPHASH_H

#include <stdint.h>
#include <stdlib.h>

void
bcn_siphash24(
  const unsigned char *data,
  size_t len,
  const unsigned char *key,
  const unsigned char *out,
  unsigned char shift
);

void
bcn_siphash(
  const unsigned char *data,
  size_t len,
  const unsigned char *key,
  unsigned char *out
);

void
bcn_siphash256(
  const unsigned char *data,
  size_t len,
  const unsigned char *key,
  unsigned char *out
);

#endif
