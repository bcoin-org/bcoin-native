'use strict';

var crypto = require('crypto');
var native = require('./');
var assert = require('assert');

process.env.BCOIN_NO_NATIVE = '1';

function bench(name) {
  var start = process.hrtime();
  return function end(ops) {
    var elapsed = process.hrtime(start);
    var time = elapsed[0] + elapsed[1] / 1e9;
    var rate = ops / time;

    console.log('%s: ops=%d, time=%d, rate=%s',
      name, ops, time, rate.toFixed(5));
  };
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function hash256(data) {
  return sha256(sha256(data));
}

function ripemd160(data) {
  return crypto.createHash('ripemd160').update(data).digest();
}

function hash160(data) {
  return ripemd160(sha256(data));
}

function sha256hmac(data, salt) {
  var hmac = crypto.createHmac('sha256', salt);
  return hmac.update(data).digest();
}

var base58 = ''
  + '123456789'
  + 'ABCDEFGHJKLMNPQRSTUVWXYZ'
  + 'abcdefghijkmnopqrstuvwxyz';

var unbase58 = {};

for (var i = 0; i < base58.length; i++)
  unbase58[base58[i]] = i;

function toBase58(data) {
  var zeroes = 0;
  var length = 0;
  var str = '';
  var i, b58, carry, j, k;

  for (i = 0; i < data.length; i++) {
    if (data[i] !== 0)
      break;
    zeroes++;
  }

  b58 = Buffer.allocUnsafe(((data.length * 138 / 100) | 0) + 1);
  b58.fill(0);

  for (; i < data.length; i++) {
    carry = data[i];
    j = 0;
    for (k = b58.length - 1; k >= 0; k--, j++) {
      if (carry === 0 && j >= length)
        break;
      carry += 256 * b58[k];
      b58[k] = carry % 58;
      carry = carry / 58 | 0;
    }
    assert(carry === 0);
    length = j;
  }

  i = b58.length - length;
  while (i < b58.length && b58[i] === 0)
    i++;

  for (j = 0; j < zeroes; j++)
    str += '1';

  for (; i < b58.length; i++)
    str += base58[b58[i]];

  return str;
}

function fromBase58(str) {
  var zeroes = 0;
  var i = 0;
  var b256, ch, carry, j, out;

  for (i = 0; i < str.length; i++) {
    if (str[i] !== '1')
      break;
    zeroes++;
  }

  b256 = Buffer.allocUnsafe(((str.length * 733) / 1000 | 0) + 1);
  b256.fill(0);

  for (; i < str.length; i++) {
    ch = unbase58[str[i]];
    if (ch == null)
      throw new Error('Non-base58 character.');

    carry = ch;
    for (j = b256.length - 1; j >= 0; j--) {
      carry += 58 * b256[j];
      b256[j] = carry % 256;
      carry = carry / 256 | 0;
    }

    assert(carry === 0);
  }

  i = 0;
  while (i < b256.length && b256[i] === 0)
    i++;

  out = Buffer.allocUnsafe(zeroes + (b256.length - i));

  for (j = 0; j < zeroes; j++)
    out[j] = 0;

  while (i < b256.length)
    out[j++] = b256[i++];

  return out;
}

var b = Buffer.allocUnsafe(400);

for (var i = 0; i < b.length; i++)
  b[i] = i & 0xff;

var k = Buffer.allocUnsafe(40);

for (var i = 0; i < k.length; i++)
  k[i] = i & 0xff;

var end = bench('crypto.sha256');
for (var i = 0; i < 100000; i++) {
  sha256(b);
}
end(i);

var end = bench('native.sha256');
for (var i = 0; i < 100000; i++) {
  native.sha256(b);
}
end(i);

var end = bench('crypto.hash160');
for (var i = 0; i < 100000; i++) {
  hash160(b);
}
end(i);

var end = bench('native.hash160');
for (var i = 0; i < 100000; i++) {
  native.hash160(b);
}
end(i);

var end = bench('crypto.hash256');
for (var i = 0; i < 100000; i++) {
  hash256(b);
}
end(i);

var end = bench('native.hash256');
for (var i = 0; i < 100000; i++) {
  native.hash256(b);
}
end(i);

var end = bench('crypto.sha256hmac');
for (var i = 0; i < 100000; i++) {
  sha256hmac(b, k);
}
end(i);

var end = bench('native.sha256hmac');
for (var i = 0; i < 100000; i++) {
  native.hmac('sha256', b, k);
}
end(i);

var end = bench('utils.toBase58');
for (var i = 0; i < 100000; i++) {
  toBase58(k);
}
end(i);

var end = bench('native.toBase58');
for (var i = 0; i < 100000; i++) {
  native.toBase58(k);
}
end(i);

var str = native.toBase58(k);

var end = bench('utils.fromBase58');
for (var i = 0; i < 100000; i++) {
  fromBase58(str);
}
end(i);

var end = bench('native.fromBase58');
for (var i = 0; i < 100000; i++) {
  native.fromBase58(str);
}
end(i);

try {
  var crypto = require('bcoin/lib/crypto/crypto');
} catch (e) {
  return;
}

var leaves = [];
for (var i = 0; i < 300; i++)
  leaves.push(crypto.randomBytes(32));

var end = bench('crypto.buildMerkleTree');
for (var i = 0; i < 1000; i++) {
  crypto.buildMerkleTree(leaves);
}
end(i);

var end = bench('native.buildMerkleTree');
for (var i = 0; i < 1000; i++) {
  native.buildMerkleTree(leaves.slice());
}
end(i);

try {
  var ccp = require('bcoin/lib/crypto/chachapoly');
} catch (e) {
  return;
}

[['js', ccp], ['c', native]].forEach(function(item) {
  var name = item[0];
  var obj = item[1];

  var poly = new obj.Poly1305();
  var key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  key = Buffer.concat([key, key]);
  poly.init(key);

  var data = Buffer.allocUnsafe(32);
  for (var i = 0; i < 32; i++)
    data[i] = i & 0xff;

  var end = bench(name + ' poly1305.update');
  for (var i = 0; i < 1000000; i++)
    poly.update(data);
  end(i * 32 / 1024);

  var end = bench(name + ' poly1305.finish');
  for (var i = 0; i < 1000000; i++) {
    poly.init(key);
    poly.update(data);
    poly.finish();
  }
  end(i * 32 / 1024);
});

try {
  var murmur3 = require('bcoin/lib/utils/murmur3');
} catch (e) {
  return;
}

[['js', {murmur3:murmur3}], ['c', native]].forEach(function(item) {
  var name = item[0];
  var obj = item[1];

  var end = bench(name + ' murmur3');
  for (var i = 0; i < 1000000; i++)
    obj.murmur3(b, 100);
  end(i);
});

try {
  var siphash = require('bcoin/lib/crypto/siphash');
} catch (e) {
  return;
}

[['js', {siphash256:siphash.siphash256}], ['c', native]].forEach(function(item) {
  var name = item[0];
  var obj = item[1];

  var u256 = b.slice(0, 32);
  var k = b.slice(32, 48);
  var end = bench(name + ' siphash256');
  for (var i = 0; i < 1000000; i++)
    obj.siphash256(u256, k);
  end(i);
});

[['js', ccp], ['c', native]].forEach(function(item) {
  var name = item[0];
  var obj = item[1];

  var chacha = new obj.ChaCha20();
  var iv = Buffer.from('0102030405060708', 'hex');
  var key = Buffer.allocUnsafe(32);
  for (var i = 0; i < 32; i++)
    key[i] = i;
  chacha.init(key, iv, 0);
  var data = Buffer.allocUnsafe(32);
  for (var i = 0; i < 32; i++)
    data[i] = i;
  var end = bench(name + ' chacha20');
  for (var i = 0; i < 1000000; i++)
    chacha.encrypt(data);
  end(i * 32 / 1024);
});
