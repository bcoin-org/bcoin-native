#ifndef _BCN_COMMON_H
#define _BCN_COMMON_H

#include <stdint.h>
#include <stdlib.h>

#define READU32(b) \
  (((uint32_t)((b)[0])) | ((uint32_t)((b)[1]) << 8) \
  | ((uint32_t)((b)[2]) << 16) | ((uint32_t)((b)[3]) << 24))

#define READU64(b) ((uint64_t)(READU32(b + 4)) << 32) | (uint64_t)(READU32(b))

#define WRITEU32(b, i) \
  ((b)[0] = i & 0xff, (b)[1] = (i >> 8) & 0xff, \
  (b)[2] = (i >> 16) & 0xff, (b)[3] = (i >> 24) & 0xff)

#define WRITEU64(b, i) (WRITEU32(b + 4, (i >> 32)), WRITEU32(b, (i & 0xffffffff)))

#endif // _BCN_COMMON_H
