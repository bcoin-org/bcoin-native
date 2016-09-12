#ifndef _BCN_HASH_H
#define _BCN_HASH_H
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/sha.h"
#include "openssl/ripemd.h"
#include "openssl/hmac.h"

#if 0
#include "openssl/kdf.h"
#endif

#define MAX_HASH_SIZE EVP_MAX_MD_SIZE

bool
bcn_hash(
  const char *name,
  const unsigned char *data,
  unsigned int len,
  unsigned char *rdata,
  unsigned int *rlen
);

bool
bcn_hmac(
  const char *name,
  const unsigned char *data,
  unsigned int len,
  const unsigned char *kdata,
  unsigned int klen,
  unsigned char *rdata,
  unsigned int *rlen
);

#if 0
bool
bcn_hkdf_extract(
  const char *name,
  const unsigned char *ikm,
  unsigned int ilen,
  const unsigned char *salt,
  unsigned int slen,
  unsigned char *rdata,
  unsigned int *rlen
);

bool
bcn_hkdf_expand(
  const char *name,
  const unsigned char *prk,
  unsigned int plen,
  const unsigned char *info,
  unsigned int ilen,
  unsigned char *rdata,
  unsigned int rlen
);
#endif

bool
bcn_sha256(const unsigned char *data, unsigned int len, unsigned char *out);

bool
bcn_rmd160(const unsigned char *data, unsigned int len, unsigned char *out);

bool
bcn_hash160(const unsigned char *data, unsigned int len, unsigned char *out);

bool
bcn_hash256(const unsigned char *data, unsigned int len, unsigned char *out);

bool
bcn_hash256_lr(const unsigned char *left, const unsigned char *right, unsigned char *out);

bool
bcn_pbkdf2(
  const char *name,
  const unsigned char *data,
  unsigned int len,
  const unsigned char *salt,
  unsigned int slen,
  unsigned int iter,
  unsigned char *rdata,
  unsigned int rlen
);
#endif
