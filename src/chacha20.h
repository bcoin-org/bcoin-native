#ifndef _BCN_CHACHA20_H
#define _BCN_CHACHA20_H

#include <node.h>
#include <nan.h>

extern "C" {
#include "chacha20-simple/chacha20_simple.h"
}

class ChaCha20 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  ChaCha20();
  ~ChaCha20();
  void InitKey(v8::Local<v8::Object> &key);
  void InitIV(v8::Local<v8::Object> &iv, v8::Local<v8::Value> &ctr);

  chacha20_ctx ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(InitIV);
  static NAN_METHOD(InitKey);
  static NAN_METHOD(Encrypt);
  static NAN_METHOD(SetCounter);
  static NAN_METHOD(GetCounter);
};
#endif
