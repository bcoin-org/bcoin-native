#ifndef _BCN_BCN_H
#define _BCN_BCN_H

#include <node.h>
#include <nan.h>

NAN_METHOD(hash);
NAN_METHOD(hmac);
NAN_METHOD(ripemd160);
NAN_METHOD(sha1);
NAN_METHOD(sha256);
NAN_METHOD(hash160);
NAN_METHOD(hash256);
NAN_METHOD(to_base58);
NAN_METHOD(from_base58);
NAN_METHOD(to_bech32);
NAN_METHOD(from_bech32);
NAN_METHOD(scrypt);
NAN_METHOD(scrypt_async);
NAN_METHOD(murmur3);
NAN_METHOD(siphash);
NAN_METHOD(siphash256);
NAN_METHOD(create_merkle_tree);
NAN_METHOD(verify_merkle_branch);
NAN_METHOD(cleanse);
NAN_METHOD(encipher);
NAN_METHOD(decipher);

#endif
