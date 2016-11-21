#ifndef _BCN_HASH_H
#define _BCN_HASH_H

#include "openssl/evp.h"

#define MAX_HASH_SIZE EVP_MAX_MD_SIZE

bool
bcn_hash(
  const char *name,
  const uint8_t *data,
  uint32_t len,
  uint8_t *rdata,
  uint32_t *rlen
);

bool
bcn_hmac(
  const char *name,
  const uint8_t *data,
  uint32_t len,
  const uint8_t *kdata,
  uint32_t klen,
  uint8_t *rdata,
  uint32_t *rlen
);

#if BCN_USE_HKDF
bool
bcn_hkdf_extract(
  const char *name,
  const uint8_t *ikm,
  uint32_t ilen,
  const uint8_t *salt,
  uint32_t slen,
  uint8_t *rdata,
  uint32_t *rlen
);

bool
bcn_hkdf_expand(
  const char *name,
  const uint8_t *prk,
  uint32_t plen,
  const uint8_t *info,
  uint32_t ilen,
  uint8_t *rdata,
  uint32_t rlen
);
#endif

bool
bcn_sha1(const uint8_t *data, uint32_t len, uint8_t *out);

bool
bcn_sha256(const uint8_t *data, uint32_t len, uint8_t *out);

bool
bcn_rmd160(const uint8_t *data, uint32_t len, uint8_t *out);

bool
bcn_hash160(const uint8_t *data, uint32_t len, uint8_t *out);

bool
bcn_hash256(const uint8_t *data, uint32_t len, uint8_t *out);

bool
bcn_hash256_lr(const uint8_t *left, const uint8_t *right, uint8_t *out);

bool
bcn_pbkdf2(
  const char *name,
  const uint8_t *data,
  uint32_t len,
  const uint8_t *salt,
  uint32_t slen,
  uint32_t iter,
  uint8_t *rdata,
  uint32_t rlen
);
#endif
