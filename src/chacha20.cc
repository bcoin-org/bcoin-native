#include "chacha20.h"

static Nan::Persistent<v8::FunctionTemplate> chacha20_constructor;

ChaCha20::ChaCha20() {
  memset(&ctx, 0, sizeof(chacha20_ctx));
  ctx.iv_size = 8;
}

ChaCha20::~ChaCha20() {}

void
ChaCha20::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(ChaCha20::New);

  chacha20_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("ChaCha20").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", ChaCha20::Init);
  Nan::SetPrototypeMethod(tpl, "initIV", ChaCha20::InitIV);
  Nan::SetPrototypeMethod(tpl, "initKey", ChaCha20::InitKey);
  Nan::SetPrototypeMethod(tpl, "encrypt", ChaCha20::Encrypt);
  Nan::SetPrototypeMethod(tpl, "setCounter", ChaCha20::SetCounter);
  Nan::SetPrototypeMethod(tpl, "getCounter", ChaCha20::GetCounter);

  v8::Local<v8::FunctionTemplate> ctor =
      Nan::New<v8::FunctionTemplate>(chacha20_constructor);

  target->Set(Nan::New("ChaCha20").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(ChaCha20::New) {
  if (!info.IsConstructCall()) {
    v8::Local<v8::FunctionTemplate> ctor =
        Nan::New<v8::FunctionTemplate>(chacha20_constructor);
    Nan::MaybeLocal<v8::Object> maybeInstance;
    v8::Local<v8::Object> instance;

    maybeInstance = Nan::NewInstance(ctor->GetFunction(), 0, NULL);

    if (maybeInstance.IsEmpty())
      return Nan::ThrowError("Could not create ChaCha20 instance.");

    instance = maybeInstance.ToLocalChecked();

    info.GetReturnValue().Set(instance);
    return;
  }
  ChaCha20* chacha = new ChaCha20();
  chacha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(ChaCha20::Init) {
  ChaCha20* chacha = ObjectWrap::Unwrap<ChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.init() requires arguments.");

  v8::Local<v8::Object> key = info[0].As<v8::Object>();

  if (!key->IsNull() && !key->IsUndefined())
    chacha->InitKey(key);

  if (info.Length() > 1) {
    v8::Local<v8::Object> iv = info[1].As<v8::Object>();
    if (!iv->IsNull() && !iv->IsUndefined()) {
      v8::Local<v8::Value> num = Nan::New<v8::Number>(0);
      if (info.Length() > 2 && info[2]->IsNumber())
        num = v8::Local<v8::Value>::Cast(info[2]);
      chacha->InitIV(iv, num);
    }
  }
}

void
ChaCha20::InitKey(v8::Local<v8::Object> &key) {
  Nan::HandleScope scope;

  if (!node::Buffer::HasInstance(key))
    return Nan::ThrowTypeError("`key` must be a Buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(key);
  size_t len = node::Buffer::Length(key);

  if (len != 32)
    return Nan::ThrowError("Invalid key size.");

  chacha20_keysetup(&ctx, data, 32);
}

void
ChaCha20::InitIV(v8::Local<v8::Object> &iv, v8::Local<v8::Value> &num) {
  Nan::HandleScope scope;

  if (!node::Buffer::HasInstance(iv))
    return Nan::ThrowTypeError("`iv` must be a Buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(iv);
  size_t len = node::Buffer::Length(iv);

  if (len != 8 && len != 12)
    return Nan::ThrowError("Invalid IV size.");

  uint64_t ctr = 0;

  if (num->IsNumber())
    ctr = (uint64_t)v8::Local<v8::Integer>::Cast(num)->Value();

  chacha20_ivsetup(&ctx, (uint8_t *)data, (uint8_t)len);
  chacha20_counter_set(&ctx, ctr);
}

NAN_METHOD(ChaCha20::InitIV) {
  ChaCha20* chacha = ObjectWrap::Unwrap<ChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.initIV() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  v8::Local<v8::Value> num = Nan::New<v8::Number>(0);
  if (info.Length() > 1)
    num = v8::Local<v8::Value>::Cast(info[1]);

  chacha->InitIV(buf, num);
}

NAN_METHOD(ChaCha20::InitKey) {
  ChaCha20* chacha = ObjectWrap::Unwrap<ChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.initKey() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  chacha->InitKey(buf);
}

NAN_METHOD(ChaCha20::Encrypt) {
  ChaCha20* chacha = ObjectWrap::Unwrap<ChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a Buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  chacha20_encrypt(&chacha->ctx, (uint8_t *)data, (uint8_t *)data, len);

  info.GetReturnValue().Set(buf);
}

NAN_METHOD(ChaCha20::SetCounter) {
  ChaCha20* chacha = ObjectWrap::Unwrap<ChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.setCounter() requires arguments.");

  v8::Local<v8::Object> num = info[0].As<v8::Object>();

  if (!num->IsNumber())
    return Nan::ThrowError("First argument must be a number.");

  uint64_t ctr = v8::Local<v8::Integer>::Cast(num)->Value();
  chacha20_counter_set(&chacha->ctx, ctr);
}

NAN_METHOD(ChaCha20::GetCounter) {
  ChaCha20* chacha = ObjectWrap::Unwrap<ChaCha20>(info.Holder());
  info.GetReturnValue().Set(
    Nan::New<v8::Number>((double)chacha20_counter_get(&chacha->ctx)));
}
