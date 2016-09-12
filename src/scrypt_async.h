#ifndef _BCN_SCRYPT_ASYNC_H
#define _BCN_SCRYPT_ASYNC_H

#include <node.h>
#include <nan.h>

class ScryptWorker : public Nan::AsyncWorker {
public:
  ScryptWorker (
    v8::Local<v8::Object> &passHandle,
    v8::Local<v8::Object> &saltHandle,
    const char *pass,
    const unsigned int passlen,
    const unsigned char *salt,
    size_t saltlen,
    uint64_t N,
    uint64_t r,
    uint64_t p,
    size_t keylen,
    Nan::Callback *callback
  );

  virtual ~ScryptWorker ();
  virtual void Execute ();
  void HandleOKCallback();

private:
  const char *pass;
  const unsigned int passlen;
  const unsigned char *salt;
  size_t saltlen;
  uint64_t N;
  uint64_t r;
  uint64_t p;
  unsigned char *key;
  size_t keylen;
};

#endif
