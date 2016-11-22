#ifndef _BCN_CIPHER_H
#define _BCN_CIPHER_H

#define BCN_ENCIPHER_SIZE(len) ((len) + (16 - ((len) % 16)));
#define BCN_DECIPHER_SIZE(len) (len)

#ifdef BCN_USE_CIPHER
bool
bcn_cipher(
  const char *name,
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint32_t keylen,
  const uint8_t *iv,
  const uint32_t ivlen,
  uint8_t **out,
  uint32_t *outlen,
  const bool encrypt
);
#endif

bool
bcn_encipher(
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint8_t *iv,
  uint8_t *out,
  uint32_t *outlen
);

bool
bcn_decipher(
  const uint8_t *data,
  const uint32_t datalen,
  const uint8_t *key,
  const uint8_t *iv,
  uint8_t *out,
  uint32_t *outlen
);
#endif
