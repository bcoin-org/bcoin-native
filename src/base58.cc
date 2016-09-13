#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <assert.h>

static const uint8_t b58_tbl[] =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool
bcn_decode_b58(
  uint8_t **data,
  size_t *datalen,
  const uint8_t *str,
  size_t strlen
) {
  int32_t zeroes = 0;
  int32_t i = 0;
  uint8_t *b256;
  int32_t ch, carry, j, slen, dlen, b256len;

  *data = NULL;
  *datalen = 0;

  assert(str != NULL);

  slen = (int32_t)strlen;

  if (slen == 0)
    return true;

  for (i = 0; i < slen; i++) {
    if (str[i] != '1')
      break;
    zeroes++;
  }

  b256len = slen * 733 / 1000 + 1;
  b256 = (uint8_t *)malloc(b256len);

  if (b256 == NULL)
    return false;

  memset(b256, 0, b256len);

  for (; i < slen; i++) {
    ch = str[i];

    // Big switch statement taken
    // from breadwallet code.
    switch (ch) {
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        ch -= '1';
        break;

      case 'A':
      case 'B':
      case 'C':
      case 'D':
      case 'E':
      case 'F':
      case 'G':
      case 'H':
        ch += 9 - 'A';
        break;

      case 'J':
      case 'K':
      case 'L':
      case 'M':
      case 'N':
        ch += 17 - 'J';
        break;

      case 'P':
      case 'Q':
      case 'R':
      case 'S':
      case 'T':
      case 'U':
      case 'V':
      case 'W':
      case 'X':
      case 'Y':
      case 'Z':
        ch += 22 - 'P';
        break;

      case 'a':
      case 'b':
      case 'c':
      case 'd':
      case 'e':
      case 'f':
      case 'g':
      case 'h':
      case 'i':
      case 'j':
      case 'k':
        ch += 33 - 'a';
        break;

      case 'm':
      case 'n':
      case 'o':
      case 'p':
      case 'q':
      case 'r':
      case 's':
      case 't':
      case 'u':
      case 'v':
      case 'w':
      case 'x':
      case 'y':
      case 'z':
        ch += 44 - 'm';
        break;

      default:
        ch = UINT32_MAX;
    }

    if (ch >= 58) {
      free(b256);
      return false;
    }

    carry = ch;
    for (j = b256len - 1; j >= 0; j--) {
      carry += 58 * b256[j];
      b256[j] = carry % 256;
      carry = carry / 256;
    }

    assert(carry == 0);
  }

  i = 0;
  while (i < b256len && b256[i] == 0)
    i++;

  dlen = zeroes + (b256len - i);
  *data = (uint8_t *)malloc(dlen);

  if (*data == NULL) {
    free(b256);
    return false;
  }

  for (j = 0; j < zeroes; j++)
    (*data)[j] = 0;

  while (i < b256len)
    (*data)[j++] = b256[i++];

  assert(j == dlen);

  *datalen = (size_t)j;

  free(b256);

  return true;
}

bool
bcn_encode_b58(
  uint8_t **str,
  size_t *strlen,
  const uint8_t *data,
  size_t datalen
) {
  int32_t zeroes = 0;
  int32_t length = 0;
  uint8_t *b58;
  int32_t b58len;
  int32_t i, carry, j, k;
  int32_t dlen = (int32_t)datalen;

  *str = NULL;
  *strlen = 0;

  assert(data != NULL);

  if (dlen == 0)
    return true;

  for (i = 0; i < dlen; i++) {
    if (data[i] != 0)
      break;
    zeroes++;
  }

  b58len = dlen * 138 / 100 + 1 + 1;
  b58 = (uint8_t *)malloc(b58len);

  if (b58 == NULL)
    return false;

  memset(b58, 0, b58len);

  for (; i < dlen; i++) {
    carry = data[i];
    j = 0;
    for (k = b58len - 1; k >= 0; k--, j++) {
      if (carry == 0 && j >= length)
        break;
      carry += 256 * b58[k];
      b58[k] = carry % 58;
      carry = carry / 58;
    }
    assert(carry == 0);
    length = j;
  }

  i = b58len - length;
  while (i < b58len && b58[i] == 0)
    i++;

  *str = (uint8_t *)malloc(zeroes + (b58len - i));

  if (*str == NULL) {
    free(b58);
    return false;
  }

  for (j = 0; j < zeroes; j++)
    (*str)[j] = '1';

  for (; i < b58len; i++)
    (*str)[j++] = b58_tbl[b58[i]];

  (*str)[j] = 0;
  *strlen = (size_t)j;

  free(b58);

  return true;
}
