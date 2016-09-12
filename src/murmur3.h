#ifndef _BCN_MURMUR_H
#define _BCN_MURMUR_H

#include <stdint.h>
#include <stdlib.h>

unsigned int
bcn_murmur3(const unsigned char *data, size_t len, unsigned int seed);

#endif
