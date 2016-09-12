#include "hash.h"

bool
bcn_hash(
  const char *name,
  const unsigned char *data,
  unsigned int len,
  unsigned char *rdata,
  unsigned int *rlen
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
  const unsigned char *data,
  unsigned int len,
  const unsigned char *kdata,
  unsigned int klen,
  unsigned char *rdata,
  unsigned int *rlen
) {
  const EVP_MD* md = EVP_get_digestbyname(name);

  if (md == NULL)
    return false;

  HMAC_CTX hmctx;

  HMAC_CTX_init(&hmctx);

  if (HMAC_Init_ex(&hmctx, kdata, klen, md, NULL) <= 0)
    return false;

  HMAC_Update(&hmctx, (const unsigned char *)data, len);

  HMAC_Final(&hmctx, rdata, rlen);
  HMAC_CTX_cleanup(&hmctx);

  return true;
}

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
) {
  const EVP_MD* md = EVP_get_digestbyname(name);

  if (md == NULL)
    return false;

  unsigned char *ret;

  ret = HKDF_Extract(
    md, salt, (size_t)slen, ikm, (size_t)ilen,
    rdata, (size_t *)&rlen);

  if (ret == NULL)
    return false;

  return true;
}

bool
bcn_hkdf_expand(
  const char *name,
  const unsigned char *prk,
  unsigned int plen,
  const unsigned char *info,
  unsigned int ilen,
  unsigned char *rdata,
  unsigned int rlen
) {
  const EVP_MD* md = EVP_get_digestbyname(name);

  if (md == NULL)
    return false;

  unsigned char *ret;

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
bcn_sha256(const unsigned char *data, unsigned int len, unsigned char *out) {
  SHA256_CTX ctx;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, data, len);
  SHA256_Final(out, &ctx);

  return true;
}

bool
bcn_rmd160(const unsigned char *data, unsigned int len, unsigned char *out) {
  RIPEMD160_CTX ctx;

  RIPEMD160_Init(&ctx);
  RIPEMD160_Update(&ctx, data, len);
  RIPEMD160_Final(out, &ctx);

  return true;
}

bool
bcn_hash160(const unsigned char *data, unsigned int len, unsigned char *out) {
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
bcn_hash256(const unsigned char *data, unsigned int len, unsigned char *out) {
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
bcn_hash256_lr(const unsigned char *left, const unsigned char *right, unsigned char *out) {
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
  const unsigned char *data,
  unsigned int len,
  const unsigned char *salt,
  unsigned int slen,
  unsigned int iter,
  unsigned char *rdata,
  unsigned int rlen
) {
  const EVP_MD* md = EVP_get_digestbyname(name);

  if (md == NULL)
    return false;

  if (PKCS5_PBKDF2_HMAC((const char *)data, len, salt, slen, iter, md, rlen, rdata) <= 0)
    return false;

  return true;
}
