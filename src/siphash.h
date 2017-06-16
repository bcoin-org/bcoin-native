#ifndef _BCN_SIPHASH_H
#define _BCN_SIPHASH_H

#include <stdint.h>
#include <stdlib.h>

uint64_t
bcn_siphash24(
  const uint8_t *data,
  size_t len,
  const uint8_t *key,
  uint8_t shift
);

uint64_t
bcn_siphash(const uint8_t *data, size_t len, const uint8_t *key);

uint64_t
bcn_siphash256(const uint8_t *data, size_t len, const uint8_t *key);

#endif
