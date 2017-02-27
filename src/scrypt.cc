#include "scrypt.h"
extern "C" {
#include "scrypt/crypto_scrypt.h"
}

bool
bcn_scrypt(
  const uint8_t *pass,
  const uint32_t passlen,
  const uint8_t *salt,
  size_t saltlen,
  uint64_t N,
  uint64_t r,
  uint64_t p,
  uint8_t *key,
  size_t keylen
) {
  int32_t result = crypto_scrypt(
    pass, passlen, salt, saltlen,
    N, r, p, key, keylen);

  return result == 0;
}

#if 0
#include "openssl/evp.h"
bool
bcn_scrypt(
  const uint8_t *pass,
  const uint32_t passlen,
  const uint8_t *salt,
  size_t saltlen,
  uint64_t N,
  uint64_t r,
  uint64_t p,
  size_t keylen,
  uint8_t *key
) {
  uint64_t maxmem = 0xffffffffffffffff;
  if (EVP_PBE_scrypt(pass, passlen, salt, saltlen, N, r, p, maxmem, key, keylen) <= 0)
    return false;
  return true;
}
#endif
