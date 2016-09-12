#ifndef _BCN_POLY1305_H
#define _BCN_POLY1305_H
#include <node.h>
#include <nan.h>

extern "C" {
#include "poly1305-donna/poly1305-donna.h"
}

class Poly1305 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  Poly1305();
  ~Poly1305();

  poly1305_context ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Finish);
  static NAN_METHOD(Auth);
  static NAN_METHOD(Verify);
};
#endif
