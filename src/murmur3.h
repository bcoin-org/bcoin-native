#ifndef _BCN_MURMUR_H
#define _BCN_MURMUR_H

#include <stdint.h>
#include <stdlib.h>

uint32_t
bcn_murmur3(const uint8_t *data, size_t len, uint32_t seed);

#endif
