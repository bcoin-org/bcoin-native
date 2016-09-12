#ifndef _BCN_BASE58_H
#define _BCN_BASE58_H

#include <stdlib.h>

bool
bcn_decode_b58(
  unsigned char **data,
  size_t *datalen,
  const unsigned char *str,
  size_t strlen
);

bool
bcn_encode_b58(
  unsigned char **str,
  size_t *strlen,
  const unsigned char *data,
  size_t datalen
);

#endif
