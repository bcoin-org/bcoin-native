/**
 * bcoin-native - fast native bindings to bitcoin functions.
 * Copyright (c) 2016, Christopher Jeffrey (MIT License)
 */

#include <node.h>
#include <nan.h>

#include "common.h"
#include "hash.h"
#include "cipher.h"
#include "base58.h"
#include "bech32.h"
#include "chacha20.h"
#include "poly1305.h"
#include "scrypt.h"
#include "scrypt_async.h"
#include "murmur3.h"
#include "siphash.h"
#include "bcn.h"

static const uint8_t ZERO_HASH[] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

NAN_METHOD(hash) {
  if (info.Length() < 2)
    return Nan::ThrowError("hash() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowError("First argument must be a string.");

  Nan::Utf8String name(info[0]);
  v8::Local<v8::Object> buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  uint8_t output[MAX_HASH_SIZE];
  uint32_t outlen;

  if (!bcn_hash(*name, data, len, output, &outlen))
    return Nan::ThrowError("Could not allocate context.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&output[0], outlen).ToLocalChecked());
}

NAN_METHOD(hmac) {
  if (info.Length() < 2)
    return Nan::ThrowError("hmac() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowError("First argument must be a string.");

  Nan::Utf8String name(info[0]);
  v8::Local<v8::Object> buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Object> kbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  const uint8_t *kdata = (uint8_t *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  uint8_t output[MAX_HASH_SIZE];
  uint32_t outlen;

  if (!bcn_hmac(*name, data, len, kdata, klen, output, &outlen))
    return Nan::ThrowError("Could not allocate context.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&output[0], outlen).ToLocalChecked());
}

NAN_METHOD(ripemd160) {
  if (info.Length() < 1)
    return Nan::ThrowError("ripemd160() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  uint8_t output[20];

  if (!bcn_rmd160(data, len, output))
    return Nan::ThrowError("Could not allocate context.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&output[0], 20).ToLocalChecked());
}

NAN_METHOD(sha1) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha1() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  uint8_t output[20];

  if (!bcn_sha1(data, len, output))
    return Nan::ThrowError("Could not allocate context.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&output[0], 20).ToLocalChecked());
}

NAN_METHOD(sha256) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha256() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  uint8_t output[32];

  if (!bcn_sha256(data, len, output))
    return Nan::ThrowError("Could not allocate context.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&output[0], 32).ToLocalChecked());
}

NAN_METHOD(hash160) {
  if (info.Length() < 1)
    return Nan::ThrowError("hash160() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  uint8_t output[32];

  if (!bcn_hash160(data, len, output))
    return Nan::ThrowError("Could not allocate context.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&output[0], 20).ToLocalChecked());
}

NAN_METHOD(hash256) {
  if (info.Length() < 1)
    return Nan::ThrowError("hash256() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  uint8_t output[32];

  if (!bcn_hash256(data, len, output))
    return Nan::ThrowError("Could not allocate context.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&output[0], 32).ToLocalChecked());
}

NAN_METHOD(to_base58) {
  if (info.Length() < 1)
    return Nan::ThrowError("to_base58() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  uint8_t *str;
  size_t slen;

  if (!bcn_encode_b58(&str, &slen, data, len))
    return Nan::ThrowError("Base58 encoding failed.");

  info.GetReturnValue().Set(
    Nan::New<v8::String>((char *)str, slen).ToLocalChecked());

  free(str);
}

NAN_METHOD(from_base58) {
  if (info.Length() < 1)
    return Nan::ThrowError("from_base58() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowError("First argument must be a string.");

  Nan::Utf8String str_(info[0]);
  const uint8_t *str = (const uint8_t *)*str_;
  size_t len = str_.length();

  uint8_t *data;
  size_t dlen;

  if (!bcn_decode_b58(&data, &dlen, str, len))
    return Nan::ThrowError("Invalid base58 string.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)data, dlen).ToLocalChecked());
}

NAN_METHOD(to_bech32) {
  if (info.Length() < 3)
    return Nan::ThrowError("to_bech32() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowError("First argument must be a string.");

  Nan::Utf8String hstr(info[0]);

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  v8::Local<v8::Object> wbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(wbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  const char *hrp = (const char *)*hstr;
  int32_t witver = (int32_t)info[1]->Int32Value();

  const uint8_t *witprog = (uint8_t *)node::Buffer::Data(wbuf);
  size_t witprog_len = node::Buffer::Length(wbuf);

  char output[93];
  size_t olen;

  if (!bcn_encode_bech32(output, hrp, witver, witprog, witprog_len))
    return Nan::ThrowError("Bech32 encoding failed.");

  olen = strlen((char *)output);

  info.GetReturnValue().Set(
    Nan::New<v8::String>((char *)output, olen).ToLocalChecked());
}

NAN_METHOD(from_bech32) {
  if (info.Length() < 2)
    return Nan::ThrowError("from_bech32() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowError("First argument must be a string.");

  if (!info[1]->IsObject())
    return Nan::ThrowError("Second argument must be an object.");

  Nan::Utf8String addr_(info[0]);
  const char *addr = (const char *)*addr_;

  v8::Local<v8::Object> ret = info[1].As<v8::Object>();

  uint8_t witprog[40];
  size_t witprog_len;
  int witver;
  char hrp[84];
  size_t hlen;

  if (!bcn_decode_bech32(&witver, witprog, &witprog_len, hrp, addr))
    return Nan::ThrowError("Invalid bech32 string.");

  hlen = strlen((char *)&hrp[0]);

  Nan::Set(ret,
    Nan::New<v8::String>("hrp").ToLocalChecked(),
    Nan::New<v8::String>((char *)&hrp[0], hlen).ToLocalChecked());

  Nan::Set(ret,
    Nan::New<v8::String>("version").ToLocalChecked(),
    Nan::New<v8::Number>(witver));

  Nan::Set(ret,
    Nan::New<v8::String>("hash").ToLocalChecked(),
    Nan::CopyBuffer((char *)&witprog[0], witprog_len).ToLocalChecked());

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(scrypt) {
  if (info.Length() < 6)
    return Nan::ThrowError("scrypt() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a number.");

  if (!info[5]->IsNumber())
    return Nan::ThrowTypeError("Sixth argument must be a number.");

  const uint8_t *pass = (const uint8_t *)node::Buffer::Data(pbuf);
  const uint32_t passlen = (const uint32_t)node::Buffer::Length(pbuf);
  const uint8_t *salt = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint64_t N = (uint64_t)info[2]->IntegerValue();
  uint64_t r = (uint64_t)info[3]->IntegerValue();
  uint64_t p = (uint64_t)info[4]->IntegerValue();
  size_t keylen = (size_t)info[5]->IntegerValue();

  uint8_t *key = (uint8_t *)malloc(keylen);

  if (key == NULL)
    return Nan::ThrowError("Could not allocate key.");

  if (!bcn_scrypt(pass, passlen, salt, saltlen, N, r, p, key, keylen))
    return Nan::ThrowError("Scrypt failed.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)key, keylen).ToLocalChecked());
}

NAN_METHOD(scrypt_async) {
  if (info.Length() < 6)
    return Nan::ThrowError("scrypt_async() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a number.");

  if (!info[5]->IsNumber())
    return Nan::ThrowTypeError("Sixth argument must be a number.");

  if (!info[6]->IsFunction())
    return Nan::ThrowTypeError("Seventh argument must be a Function.");

  v8::Local<v8::Function> callback = info[6].As<v8::Function>();

  const uint8_t *pass = (const uint8_t *)node::Buffer::Data(pbuf);
  const uint32_t passlen = (const uint32_t)node::Buffer::Length(pbuf);
  const uint8_t *salt = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint64_t N = (uint64_t)info[2]->IntegerValue();
  uint64_t r = (uint64_t)info[3]->IntegerValue();
  uint64_t p = (uint64_t)info[4]->IntegerValue();
  size_t keylen = (size_t)info[5]->IntegerValue();

  ScryptWorker* worker = new ScryptWorker(
    pbuf,
    sbuf,
    pass,
    passlen,
    salt,
    saltlen,
    N,
    r,
    p,
    keylen,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(murmur3) {
  if (info.Length() < 2)
    return Nan::ThrowError("murmur3() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);
  uint32_t seed = (uint32_t)info[1]->Uint32Value();

  info.GetReturnValue().Set(
    Nan::New<v8::Number>((double)bcn_murmur3(data, len, seed)));
}

NAN_METHOD(siphash) {
  if (info.Length() < 2)
    return Nan::ThrowError("siphash() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  const uint8_t *kdata = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  if (klen < 16)
    return Nan::ThrowError("Bad key size for siphash.");

  uint64_t result = bcn_siphash(data, len, kdata);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  ret->Set(0, Nan::New<v8::Int32>((int32_t)(result >> 32)));
  ret->Set(1, Nan::New<v8::Int32>((int32_t)(result & 0xffffffff)));

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(siphash256) {
  if (info.Length() < 2)
    return Nan::ThrowError("siphash256() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  const uint8_t *kdata = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  if (klen < 16)
    return Nan::ThrowError("Bad key size for siphash.");

  uint64_t result = bcn_siphash256(data, len, kdata);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  ret->Set(0, Nan::New<v8::Int32>((int32_t)(result >> 32)));
  ret->Set(1, Nan::New<v8::Int32>((int32_t)(result & 0xffffffff)));

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(create_merkle_tree) {
  if (info.Length() < 1)
    return Nan::ThrowError("create_merkle_tree() requires arguments.");

  if (!info[0]->IsArray())
    return Nan::ThrowTypeError("First argument must be an array.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  v8::Local<v8::Array> nodes = info[0].As<v8::Array>();
  uint32_t len = nodes->Length();
  uint32_t size = len;
  uint32_t i, j, k;
  uint8_t *left, *right;
  uint8_t hash[32];
  bool malleated = false;
  v8::Local<v8::Object> lbuf;
  v8::Local<v8::Object> rbuf;
  v8::Local<v8::Object> hbuf;

  if (size == 0) {
    hbuf = Nan::CopyBuffer((char *)&ZERO_HASH[0], 32).ToLocalChecked();
    nodes->Set(0, hbuf);
    ret->Set(0, nodes);
    ret->Set(1, Nan::New<v8::Boolean>(malleated));
    info.GetReturnValue().Set(ret);
    return;
  }

  for (j = 0; size > 1; size = (size + 1) >> 1) {
    for (i = 0; i < size; i += 2) {
      k = std::min(i + 1, size - 1);
      lbuf = nodes->Get(j + i).As<v8::Object>();
      rbuf = nodes->Get(j + k).As<v8::Object>();

      if (!node::Buffer::HasInstance(lbuf) || node::Buffer::Length(lbuf) != 32)
        return Nan::ThrowTypeError("Left node is not a buffer.");

      if (!node::Buffer::HasInstance(rbuf) || node::Buffer::Length(rbuf) != 32)
        return Nan::ThrowTypeError("Right node is not a buffer.");

      left = (uint8_t *)node::Buffer::Data(lbuf);
      right = (uint8_t *)node::Buffer::Data(rbuf);

      if (k == i + 1 && k + 1 == size
          && memcmp(left, right, 32) == 0) {
        malleated = true;
      }

      if (!bcn_hash256_lr(left, right, hash))
        return Nan::ThrowError("Cannot hash nodes.");

      hbuf = Nan::CopyBuffer((char *)&hash[0], 32).ToLocalChecked();
      nodes->Set(len++, hbuf);
    }
    j += size;
  }

  ret->Set(0, nodes);
  ret->Set(1, Nan::New<v8::Boolean>(malleated));

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(verify_merkle_branch) {
  if (info.Length() < 3)
    return Nan::ThrowError("verify_merkle_branch() requires arguments.");

  if (!node::Buffer::HasInstance(info[0]))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsArray())
    return Nan::ThrowTypeError("Second argument must be an array.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  v8::Local<v8::Object> hbuf = info[0].As<v8::Object>();
  v8::Local<v8::Array> branch = info[1].As<v8::Array>();

  if (!node::Buffer::HasInstance(hbuf) || node::Buffer::Length(hbuf) != 32)
    return Nan::ThrowTypeError("Node is not a buffer.");

  uint32_t index = (uint32_t)info[2]->Uint32Value();
  uint32_t len = branch->Length();
  uint32_t i;
  uint8_t hash[32];
  uint8_t *otherside;

  if (len == 0) {
    info.GetReturnValue().Set(hbuf);
    return;
  }

  memcpy(hash, node::Buffer::Data(hbuf), 32);

  for (i = 0; i < len; i++) {
    hbuf = branch->Get(i).As<v8::Object>();

    if (!node::Buffer::HasInstance(hbuf) || node::Buffer::Length(hbuf) != 32)
      return Nan::ThrowTypeError("Node is not a buffer.");

    otherside = (uint8_t *)node::Buffer::Data(hbuf);

    if (index & 1) {
      if (!bcn_hash256_lr(otherside, hash, hash))
        return Nan::ThrowError("Cannot hash nodes.");
    } else {
      if (!bcn_hash256_lr(hash, otherside, hash))
        return Nan::ThrowError("Cannot hash nodes.");
    }

    index >>= 1;
  }

  hbuf = Nan::CopyBuffer((char *)&hash[0], 32).ToLocalChecked();

  info.GetReturnValue().Set(hbuf);
}

NAN_METHOD(cleanse) {
  if (info.Length() < 1)
    return Nan::ThrowError("cleanse() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  OPENSSL_cleanse((void *)data, len);
}

NAN_METHOD(encipher) {
  if (info.Length() < 3)
    return Nan::ThrowError("encipher() requires arguments.");

  if (!node::Buffer::HasInstance(info[0]))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(info[1]))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!node::Buffer::HasInstance(info[2]))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  v8::Local<v8::Object> bdata = info[0].As<v8::Object>();
  v8::Local<v8::Object> bkey = info[1].As<v8::Object>();
  v8::Local<v8::Object> biv = info[2].As<v8::Object>();

  uint8_t *data = (uint8_t *)node::Buffer::Data(bdata);
  size_t dlen = node::Buffer::Length(bdata);

  const uint8_t *key = (uint8_t *)node::Buffer::Data(bkey);
  size_t klen = node::Buffer::Length(bkey);

  const uint8_t *iv = (uint8_t *)node::Buffer::Data(biv);
  size_t ilen = node::Buffer::Length(biv);

  if (klen != 32)
    return Nan::ThrowError("Bad key size.");

  if (ilen != 16)
    return Nan::ThrowError("Bad IV size.");

  uint32_t olen = BCN_ENCIPHER_SIZE(dlen);
  uint8_t *out = (uint8_t *)malloc(olen);

  if (out == NULL)
    return Nan::ThrowError("Could not allocate ciphertext.");

  if (!bcn_encipher(data, dlen, key, iv, out, &olen))
    return Nan::ThrowTypeError("Encipher failed.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, olen).ToLocalChecked());
}

NAN_METHOD(decipher) {
  if (info.Length() < 3)
    return Nan::ThrowError("decipher() requires arguments.");

  if (!node::Buffer::HasInstance(info[0]))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(info[1]))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!node::Buffer::HasInstance(info[2]))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  v8::Local<v8::Object> bdata = info[0].As<v8::Object>();
  v8::Local<v8::Object> bkey = info[1].As<v8::Object>();
  v8::Local<v8::Object> biv = info[2].As<v8::Object>();

  uint8_t *data = (uint8_t *)node::Buffer::Data(bdata);
  size_t dlen = node::Buffer::Length(bdata);

  const uint8_t *key = (uint8_t *)node::Buffer::Data(bkey);
  size_t klen = node::Buffer::Length(bkey);

  const uint8_t *iv = (uint8_t *)node::Buffer::Data(biv);
  size_t ilen = node::Buffer::Length(biv);

  if (klen != 32)
    return Nan::ThrowError("Bad key size.");

  if (ilen != 16)
    return Nan::ThrowError("Bad IV size.");

  uint32_t olen = BCN_DECIPHER_SIZE(dlen);
  uint8_t *out = (uint8_t *)malloc(olen);

  if (out == NULL)
    return Nan::ThrowError("Could not allocate plaintext.");

  if (!bcn_decipher(data, dlen, key, iv, out, &olen))
    return Nan::ThrowTypeError("Decipher failed.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, olen).ToLocalChecked());
}

NAN_MODULE_INIT(init) {
  Nan::Export(target, "_hash", hash);
  Nan::Export(target, "_hmac", hmac);
  Nan::Export(target, "ripemd160", ripemd160);
  Nan::Export(target, "sha1", sha1);
  Nan::Export(target, "sha256", sha256);
  Nan::Export(target, "hash160", hash160);
  Nan::Export(target, "hash256", hash256);
  Nan::Export(target, "toBase58", to_base58);
  Nan::Export(target, "fromBase58", from_base58);
  Nan::Export(target, "toBech32", to_bech32);
  Nan::Export(target, "_fromBech32", from_bech32);
  Nan::Export(target, "scrypt", scrypt);
  Nan::Export(target, "_scryptAsync", scrypt_async);
  Nan::Export(target, "murmur3", murmur3);
  Nan::Export(target, "siphash", siphash);
  Nan::Export(target, "siphash256", siphash256);
  Nan::Export(target, "createMerkleTree", create_merkle_tree);
  Nan::Export(target, "verifyMerkleBranch", verify_merkle_branch);
  Nan::Export(target, "cleanse", cleanse);
  Nan::Export(target, "encipher", encipher);
  Nan::Export(target, "decipher", decipher);

  ChaCha20::Init(target);
  Poly1305::Init(target);
}

NODE_MODULE(bcn, init)
