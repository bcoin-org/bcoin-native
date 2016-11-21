#include <stdint.h>

#include "hash.h"
#include "common.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/sha.h"
#include "openssl/ripemd.h"
#include "openssl/hmac.h"

#if BCN_USE_HKDF
#include "openssl/kdf.h"
#endif

bool
bcn_hash(
  const char *name,
  const uint8_t *data,
  uint32_t len,
  uint8_t *rdata,
  uint32_t *rlen
) {
  const EVP_MD* md = EVP_get_digestbyname(name);

  if (md == NULL)
    return false;

  EVP_MD_CTX mdctx;

  EVP_MD_CTX_init(&mdctx);

  if (EVP_DigestInit_ex(&mdctx, md, NULL) <= 0)
    return false;

  EVP_DigestUpdate(&mdctx, data, len);

  EVP_DigestFinal_ex(&mdctx, rdata, rlen);
  EVP_MD_CTX_cleanup(&mdctx);

  return true;
}

bool
bcn_hmac(
  const char *name,
  const uint8_t *data,
  uint32_t len,
  const uint8_t *kdata,
  uint32_t klen,
  uint8_t *rdata,
  uint32_t *rlen
) {
  const EVP_MD* md = EVP_get_digestbyname(name);

  if (md == NULL)
    return false;

  HMAC_CTX hmctx;

  HMAC_CTX_init(&hmctx);

  if (HMAC_Init_ex(&hmctx, kdata, klen, md, NULL) <= 0)
    return false;

  HMAC_Update(&hmctx, data, len);

  HMAC_Final(&hmctx, rdata, rlen);
  HMAC_CTX_cleanup(&hmctx);

  return true;
}

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
) {
  const EVP_MD* md = EVP_get_digestbyname(name);
  uint8_t *ret;

  if (md == NULL)
    return false;

  ret = HKDF_Extract(
    md, salt, (size_t)slen, ikm, (size_t)ilen,
    rdata, (size_t *)&rlen);

  if (ret == NULL)
    return false;

  return true;
}

bool
bcn_hkdf_expand(
  const uint8_t *name,
  const uint8_t *prk,
  uint32_t plen,
  const uint8_t *info,
  uint32_t ilen,
  uint8_t *rdata,
  uint32_t rlen
) {
  const EVP_MD* md = EVP_get_digestbyname(name);
  uint8_t *ret;

  if (md == NULL)
    return false;

  ret = HKDF_Expand(
    md, prk, (size_t)plen, info, (size_t)ilen,
    rdata, (size_t)rlen);

  if (ret == NULL)
    return false;

  return true;
}
#endif

bool
bcn_sha1(const uint8_t *data, uint32_t len, uint8_t *out) {
  SHA_CTX ctx;

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, data, len);
  SHA1_Final(out, &ctx);

  return true;
}

bool
bcn_sha256(const uint8_t *data, uint32_t len, uint8_t *out) {
  SHA256_CTX ctx;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, data, len);
  SHA256_Final(out, &ctx);

  return true;
}

bool
bcn_rmd160(const uint8_t *data, uint32_t len, uint8_t *out) {
  RIPEMD160_CTX ctx;

  RIPEMD160_Init(&ctx);
  RIPEMD160_Update(&ctx, data, len);
  RIPEMD160_Final(out, &ctx);

  return true;
}

bool
bcn_hash160(const uint8_t *data, uint32_t len, uint8_t *out) {
  SHA256_CTX sctx;

  SHA256_Init(&sctx);
  SHA256_Update(&sctx, data, len);
  SHA256_Final(out, &sctx);

  RIPEMD160_CTX rctx;

  RIPEMD160_Init(&rctx);
  RIPEMD160_Update(&rctx, out, 32);
  RIPEMD160_Final(out, &rctx);

  return true;
}

bool
bcn_hash256(const uint8_t *data, uint32_t len, uint8_t *out) {
  SHA256_CTX ctx;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, data, len);
  SHA256_Final(out, &ctx);

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, out, 32);
  SHA256_Final(out, &ctx);

  return true;
}

bool
bcn_hash256_lr(const uint8_t *left, const uint8_t *right, uint8_t *out) {
  SHA256_CTX ctx;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, left, 32);
  SHA256_Update(&ctx, right, 32);
  SHA256_Final(out, &ctx);

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, out, 32);
  SHA256_Final(out, &ctx);

  return true;
}

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
) {
  const EVP_MD* md = EVP_get_digestbyname(name);
  uint32_t ret;

  if (md == NULL)
    return false;

  ret = PKCS5_PBKDF2_HMAC(
    (const char *)data, len, salt,
    slen, iter, md, rlen, rdata);

  if (ret <= 0)
    return false;

  return true;
}
