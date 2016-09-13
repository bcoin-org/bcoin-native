/**
 * bcoin-native - fast native bindings to bitcoin functions.
 * Copyright (c) 2016, Christopher Jeffrey (MIT License)
 */

#include <node.h>
#include <nan.h>

#include "common.h"
#include "hash.h"
#include "base58.h"
#include "chacha20.h"
#include "poly1305.h"
#include "scrypt.h"
#include "scrypt_async.h"
#include "murmur3.h"
#include "siphash.h"
#include "bcn.h"

NAN_METHOD(hash) {
  if (info.Length() < 2)
    return Nan::ThrowError("hash() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowError("First argument must be a string.");

  Nan::Utf8String name(info[0]);
  v8::Local<v8::Object> buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("Second argument must be a Buffer.");

  const unsigned char *data = (unsigned char *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  unsigned char output[MAX_HASH_SIZE];
  unsigned int outlen;

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
    return Nan::ThrowTypeError("Second argument must be a Buffer.");

  v8::Local<v8::Object> kbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Third argument must be a Buffer.");

  const unsigned char *data = (unsigned char *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  const unsigned char *kdata = (unsigned char *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  unsigned char output[MAX_HASH_SIZE];
  unsigned int outlen;

  if (!bcn_hmac(*name, data, len, kdata, klen, output, &outlen))
    return Nan::ThrowError("Could not allocate context.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&output[0], outlen).ToLocalChecked());
}

NAN_METHOD(sha256) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha256() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  const unsigned char *data = (unsigned char *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  unsigned char output[32];

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
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  const unsigned char *data = (unsigned char *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  unsigned char output[32];

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
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  const unsigned char *data = (unsigned char *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  unsigned char output[32];

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
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  const unsigned char *data = (unsigned char *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  unsigned char *str;
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
  const unsigned char *str = (const unsigned char *)*str_;
  size_t len = str_.length();

  unsigned char *data;
  size_t dlen;

  if (!bcn_decode_b58(&data, &dlen, str, len))
    return Nan::ThrowError("Invalid base58 string.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)data, dlen).ToLocalChecked());
}

NAN_METHOD(scrypt) {
  if (info.Length() < 1)
    return Nan::ThrowError("to_base58() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Second argument must be a Buffer.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a Number.");

  v8::Local<v8::Value> nval = v8::Local<v8::Value>::Cast(info[2]);

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a Number.");

  v8::Local<v8::Value> rval = v8::Local<v8::Value>::Cast(info[3]);

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a Number.");

  v8::Local<v8::Value> pval = v8::Local<v8::Value>::Cast(info[4]);

  if (!info[5]->IsNumber())
    return Nan::ThrowTypeError("Sixth argument must be a Number.");

  v8::Local<v8::Value> kval = v8::Local<v8::Value>::Cast(info[5]);

  const char *pass = (const char *)node::Buffer::Data(pbuf);
  const unsigned int passlen = (const unsigned int)node::Buffer::Length(pbuf);
  const unsigned char *salt = (const unsigned char *)node::Buffer::Data(sbuf);
  size_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint64_t N = (uint64_t)v8::Local<v8::Integer>::Cast(nval)->Value();
  uint64_t r = (uint64_t)v8::Local<v8::Integer>::Cast(rval)->Value();
  uint64_t p = (uint64_t)v8::Local<v8::Integer>::Cast(pval)->Value();
  size_t keylen = (size_t)v8::Local<v8::Integer>::Cast(kval)->Value();

  unsigned char *key = (unsigned char *)malloc(keylen);

  if (key == NULL)
    return Nan::ThrowError("Could not allocate key.");

  if (!bcn_scrypt(pass, passlen, salt, saltlen, N, r, p, key, keylen))
    return Nan::ThrowError("Scrypt failed.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)key, keylen).ToLocalChecked());
}

NAN_METHOD(scrypt_async) {
  if (info.Length() < 1)
    return Nan::ThrowError("to_base58() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Second argument must be a Buffer.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a Number.");

  v8::Local<v8::Value> nval = v8::Local<v8::Value>::Cast(info[2]);

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a Number.");

  v8::Local<v8::Value> rval = v8::Local<v8::Value>::Cast(info[3]);

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a Number.");

  v8::Local<v8::Value> pval = v8::Local<v8::Value>::Cast(info[4]);

  if (!info[5]->IsNumber())
    return Nan::ThrowTypeError("Sixth argument must be a Number.");

  v8::Local<v8::Value> kval = v8::Local<v8::Value>::Cast(info[5]);

  if (!info[6]->IsFunction())
    return Nan::ThrowTypeError("Seventh argument must be a Function.");

  v8::Local<v8::Function> callback = info[6].As<v8::Function>();

  const char *pass = (const char *)node::Buffer::Data(pbuf);
  const unsigned int passlen = (const unsigned int)node::Buffer::Length(pbuf);
  const unsigned char *salt = (const unsigned char *)node::Buffer::Data(sbuf);
  size_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint64_t N = (uint64_t)v8::Local<v8::Integer>::Cast(nval)->Value();
  uint64_t r = (uint64_t)v8::Local<v8::Integer>::Cast(rval)->Value();
  uint64_t p = (uint64_t)v8::Local<v8::Integer>::Cast(pval)->Value();
  size_t keylen = (size_t)v8::Local<v8::Integer>::Cast(kval)->Value();

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
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a Number.");

  v8::Local<v8::Value> sval = v8::Local<v8::Value>::Cast(info[1]);

  const unsigned char *data = (const unsigned char *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);
  unsigned int seed = (unsigned int)v8::Local<v8::Integer>::Cast(sval)->Value();

  info.GetReturnValue().Set(
    Nan::New<v8::Number>((double)bcn_murmur3(data, len, seed)));
}

NAN_METHOD(siphash) {
  if (info.Length() < 2)
    return Nan::ThrowError("siphash() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  const unsigned char *data = (const unsigned char *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  const unsigned char *kdata = (const unsigned char *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  if (klen < 16)
    return Nan::ThrowError("Bad key size for siphash.");

  unsigned char output[8];
  bcn_siphash(data, len, kdata, output);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&output[0], 8).ToLocalChecked());
}

NAN_METHOD(siphash256) {
  if (info.Length() < 2)
    return Nan::ThrowError("siphash256() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  const unsigned char *data = (const unsigned char *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  const unsigned char *kdata = (const unsigned char *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  if (klen < 16)
    return Nan::ThrowError("Bad key size for siphash.");

  unsigned char output[8];
  bcn_siphash256(data, len, kdata, output);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&output[0], 8).ToLocalChecked());
}

NAN_METHOD(build_merkle_tree) {
  if (info.Length() < 1)
    return Nan::ThrowError("build_merkle_tree() requires arguments.");

  if (!info[0]->IsArray())
    return Nan::ThrowTypeError("First argument must be an Array.");

  v8::Local<v8::Array> tree = v8::Local<v8::Array>::Cast(info[0]);
  unsigned int len = tree->Length();
  unsigned int size = len;
  unsigned int i, j, i2;
  unsigned char *left, *right;
  unsigned char hash[32];
  v8::Local<v8::Object> lbuf;
  v8::Local<v8::Object> rbuf;
  v8::Local<v8::Object> hbuf;

  for (j = 0; size > 1; size = (size + 1) / 2) {
    for (i = 0; i < size; i += 2) {
      i2 = std::min(i + 1, size - 1);
      lbuf = tree->Get(j + i).As<v8::Object>();
      rbuf = tree->Get(j + i2).As<v8::Object>();

      if (!node::Buffer::HasInstance(lbuf) || node::Buffer::Length(lbuf) != 32)
        return Nan::ThrowTypeError("Left node is not a buffer.");

      if (!node::Buffer::HasInstance(rbuf) || node::Buffer::Length(rbuf) != 32)
        return Nan::ThrowTypeError("Right node is not a buffer.");

      left = (unsigned char *)node::Buffer::Data(lbuf);
      right = (unsigned char *)node::Buffer::Data(rbuf);

      if (i2 == i + 1 && i2 + 1 == size
          && memcmp(left, right, 32) == 0) {
        info.GetReturnValue().Set(Nan::Null());
        return;
      }

      if (!bcn_hash256_lr(left, right, hash))
        return Nan::ThrowError("Cannot hash nodes.");

      hbuf = Nan::CopyBuffer((char *)&hash[0], 32).ToLocalChecked();
      tree->Set(len++, hbuf);
    }
    j += size;
  }

  if (len == 0) {
    info.GetReturnValue().Set(Nan::Null());
    return;
  }

  info.GetReturnValue().Set(tree);
}

NAN_METHOD(check_merkle_branch) {
  if (info.Length() < 3)
    return Nan::ThrowError("check_merkle_branch() requires arguments.");

  if (!node::Buffer::HasInstance(info[0]))
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  if (!info[1]->IsArray())
    return Nan::ThrowTypeError("Second argument must be an Array.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a Number.");

  v8::Local<v8::Object> hbuf = info[0].As<v8::Object>();
  v8::Local<v8::Array> branch = v8::Local<v8::Array>::Cast(info[1]);
  v8::Local<v8::Value> ib = v8::Local<v8::Value>::Cast(info[2]);

  if (!node::Buffer::HasInstance(hbuf) || node::Buffer::Length(hbuf) != 32)
    return Nan::ThrowTypeError("Node is not a buffer.");

  unsigned int index = (unsigned int)v8::Local<v8::Integer>::Cast(ib)->Value();
  unsigned int len = branch->Length();
  unsigned int i;
  unsigned char hash[32];
  unsigned char *otherside;

  if (len == 0) {
    info.GetReturnValue().Set(hbuf);
    return;
  }

  memcpy(hash, node::Buffer::Data(hbuf), 32);

  for (i = 0; i < len; i++) {
    hbuf = branch->Get(i).As<v8::Object>();

    if (!node::Buffer::HasInstance(hbuf) || node::Buffer::Length(hbuf) != 32)
      return Nan::ThrowTypeError("Node is not a buffer.");

    otherside = (unsigned char *)node::Buffer::Data(hbuf);

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

NAN_MODULE_INIT(init) {
  Nan::Export(target, "hash", hash);
  Nan::Export(target, "hmac", hmac);
  Nan::Export(target, "sha256", sha256);
  Nan::Export(target, "hash160", hash160);
  Nan::Export(target, "hash256", hash256);
  Nan::Export(target, "toBase58", to_base58);
  Nan::Export(target, "fromBase58", from_base58);
  Nan::Export(target, "scrypt", scrypt);
  Nan::Export(target, "scryptAsync", scrypt_async);
  Nan::Export(target, "murmur3", murmur3);
  Nan::Export(target, "siphash", siphash);
  Nan::Export(target, "siphash256", siphash256);
  Nan::Export(target, "buildMerkleTree", build_merkle_tree);
  Nan::Export(target, "checkMerkleBranch", check_merkle_branch);

  ChaCha20::Init(target);
  Poly1305::Init(target);
}

NODE_MODULE(bcn, init)
