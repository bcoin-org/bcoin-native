#include "scrypt.h"
#include "scrypt_async.h"

ScryptWorker::ScryptWorker (
  v8::Local<v8::Object> &passHandle,
  v8::Local<v8::Object> &saltHandle,
  const char *pass,
  const unsigned int passlen,
  const unsigned char *salt,
  size_t saltlen,
  unsigned long long N,
  unsigned long long r,
  unsigned long long p,
  size_t keylen,
  Nan::Callback *callback
) : Nan::AsyncWorker(callback)
  , pass(pass)
  , passlen(passlen)
  , salt(salt)
  , saltlen(saltlen)
  , N(N)
  , r(r)
  , p(p)
  , key(NULL)
  , keylen(keylen)
{
  Nan::HandleScope scope;
  SaveToPersistent("pass", passHandle);
  SaveToPersistent("salt", saltHandle);
}

ScryptWorker::~ScryptWorker() {}

void ScryptWorker::Execute() {
  key = (unsigned char *)malloc(keylen);

  if (key == NULL) {
    SetErrorMessage("Scrypt failed.");
    return;
  }

  if (!bcn_scrypt(pass, passlen, salt, saltlen, N, r, p, key, keylen)) {
    free(key);
    key = NULL;
    SetErrorMessage("Scrypt failed.");
  }
}

void ScryptWorker::HandleOKCallback() {
  Nan::HandleScope scope;

  v8::Local<v8::Value> keyBuffer =
    Nan::NewBuffer((char*)key, keylen).ToLocalChecked();

  v8::Local<v8::Value> argv[] = { Nan::Null(), keyBuffer };

  callback->Call(2, argv);
}
