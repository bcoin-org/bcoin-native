#ifndef _BCN_SIPHASH_H
#define _BCN_SIPHASH_H

#include <stdint.h>
#include <stdlib.h>

void
bcn_siphash24(
  const uint8_t *data,
  size_t len,
  const uint8_t *key,
  const uint8_t *out,
  uint8_t shift
);

void
bcn_siphash(const uint8_t *data, size_t len, const uint8_t *key, uint8_t *out);

void
bcn_siphash256(const uint8_t *data, size_t len, const uint8_t *key, uint8_t *out);

#endif
