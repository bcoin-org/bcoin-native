#include "scrypt.h"
extern "C" {
#include "scrypt/scrypt.h"
}

bool
bcn_scrypt(
  const char *pass,
  const unsigned int passlen,
  const unsigned char *salt,
  size_t saltlen,
  uint64_t N,
  uint64_t r,
  uint64_t p,
  unsigned char *key,
  size_t keylen
) {
  int result = crypto_scrypt(
    (uint8_t *)pass, passlen,
    (uint8_t *)salt, saltlen,
    N, r, p, (uint8_t *)key,
    keylen);

  return result == 0;
}

#if 0
#include "openssl/evp.h"
bool
bcn_scrypt(
  const char *pass,
  const unsigned int passlen,
  const unsigned char *salt,
  size_t saltlen,
  uint64_t N,
  uint64_t r,
  uint64_t p,
  size_t keylen,
  unsigned char *key
) {
  uint64_t maxmem = 0xffffffffffffffff;
  if (EVP_PBE_scrypt(pass, passlen, salt, saltlen, N, r, p, maxmem, key, keylen) <= 0)
    return false;
  return true;
}
#endif
