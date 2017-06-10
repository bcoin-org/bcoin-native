'use strict';

var crypto = require('crypto');
var native = require('./');
var assert = require('assert');

process.env.BCOIN_NO_NATIVE = '1';

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function hash256(data) {
  return sha256(sha256(data));
}

function sha256hmac(data, salt) {
  var hmac = crypto.createHmac('sha256', salt);
  return hmac.update(data).digest();
}

var b = Buffer.allocUnsafe(400);

for (var i = 0; i < b.length; i++)
  b[i] = i & 0xff;

var k = Buffer.allocUnsafe(40);

for (var i = 0; i < k.length; i++)
  k[i] = i & 0xff;

assert.strictEqual(
  native.toBase58(k),
  '1fAhYWqs6ctsWHNZtpYJNB9BxxQPq4Pa5LkbLC3wpAHLipXE7tXVY'
);

assert.deepStrictEqual(
  native.fromBase58(native.toBase58(k)),
  k
);

assert.strictEqual(
  hash256(b).toString('hex'),
  native.hash256(b).toString('hex'));

assert.strictEqual(
  sha256(b).toString('hex'),
  native.sha256(b).toString('hex'));

assert.strictEqual(
  sha256(b).toString('hex'),
  native.hash('sha256', b).toString('hex'));

assert.strictEqual(
  sha256hmac(b, k).toString('hex'),
  native.hmac('sha256', b, k).toString('hex'));

assert.throws(function() {
  native.sha256(1);
});

assert.throws(function() {
  native.hash256(1);
});

assert.throws(function() {
  native.sha256();
});

assert.throws(function() {
  native.hash256();
});

var result = native.scrypt(Buffer.from('password'), Buffer.from('NaCl'), 1024, 8, 16, 64);
assert.equal(result.toString('hex'), ''
  + 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e773'
  + '76634b3731622eaf30d92e22a3886ff109279d9830dac727afb9'
  + '4a83ee6d8360cbdfa2cc0640');

native.scryptAsync(Buffer.from('password'), Buffer.from('NaCl'), 1024, 8, 16, 64).then(function(result) {
  assert.equal(result.toString('hex'), ''
    + 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e773'
    + '76634b3731622eaf30d92e22a3886ff109279d9830dac727afb9'
    + '4a83ee6d8360cbdfa2cc0640');
}).catch(function(err) { throw err; });

try {
  var murmur3 = require('bcoin/lib/primitives/bloom').murmur3;
} catch (e) {
  return;
}

assert.equal(murmur3(k, 1), native.murmur3(k, 1));

try {
  var siphash = require('bcoin/lib/crypto/siphash');
} catch (e) {
  return;
}

assert.deepStrictEqual(
  siphash.siphash256(b.slice(0, 32), k.slice(0, 16)),
  native.siphash256(b.slice(0, 32), k.slice(0, 16))
);

assert.deepStrictEqual(
  siphash.siphash(b.slice(0, 88), k.slice(0, 16)),
  native.siphash(b.slice(0, 88), k.slice(0, 16))
);

try {
  var ccp = require('bcoin/lib/crypto/chachapoly');
} catch (e) {
  return;
}

var key = k.slice(0, 32);
var poly = new ccp.Poly1305();
poly.init(key);
poly.update(b);
var out1 = poly.finish();

var key = k.slice(0, 32);
var poly = new native.Poly1305();
poly.init(key);
poly.update(b);
var out2 = poly.finish();
assert.deepStrictEqual(out1, out2);
assert(native.Poly1305.verify(out1, out2));

var key = k.slice(0, 32);
var iv = k.slice(0, 8);
var chacha = new ccp.ChaCha20();
chacha.init(key, iv);
var out1 = Buffer.from(b);
chacha.encrypt(out1);

var key = k.slice(0, 32);
var iv = k.slice(0, 8);
var chacha = new native.ChaCha20();
chacha.init(key, iv);
var out2 = Buffer.from(b);
chacha.encrypt(out2);
assert.deepStrictEqual(out1, out2);
