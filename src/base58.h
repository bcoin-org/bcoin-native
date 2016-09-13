#ifndef _BCN_BASE58_H
#define _BCN_BASE58_H

#include <stdlib.h>

bool
bcn_decode_b58(
  uint8_t **data,
  size_t *datalen,
  const uint8_t *str,
  size_t strlen
);

bool
bcn_encode_b58(
  uint8_t **str,
  size_t *strlen,
  const uint8_t *data,
  size_t datalen
);

#endif
