# bcoin-native

The missing crypto and encoding bindings for node.js.

This module provides _native bindings_ to all lowlevel optimizable things used
in bitcoin.

Used in [bcoin][bcoin].

## Functions
  - `hash(alg, data)`
  - `hmac(alg, data)`
  - `ripemd160(data)`
  - `sha1(data)`
  - `sha256(data)`
  - `hash160(data)`
  - `hash256(data)`
  - `toBase58(data)`
  - `fromBase58(data)`
  - `toBech32(hrp, version, hash)`
  - `fromBech32(str)`
  - `scrypt(pass, salt, n, r, p, klen)`
  - `scryptAsync(pass, salt, n, r, p, klen)`
  - `murmur3(data, seed)`
  - `siphash(data, key)`
  - `siphash256(data, key)`
  - `buildMerkleTree(leaves)`
  - `checkMerkleBranch(hash, branch, index)`
  - `cleanse(data)`
  - `encipher(data, key, iv)`
  - `decipher(data, key, iv)`

## Objects
  - `Poly1305()`
    - `#init(key)`
    - `#update(data)`
    - `#finish()`
    - `.verify(mac1, mac2)`
    - `.auth(data, key)`
  - `ChaCha20()`
    - `#init(key?, iv?, counter?)`
    - `#initKey(key)`
    - `#initIV(iv, counter?)`
    - `#encrypt(data)`
    - `#getCounter()`
    - `#setCounter(counter)`

## Usage

``` js
var native = require('bcoin-native');
var data = Buffer.from('01020304', 'hex');
var key = Buffer.from('05060708', 'hex');

var hash1 = native.sha256(data);
var hash2 = native.hash256(data);

console.log('sha256: %s', hash1.toString('hex'));
console.log('double sha256: %s', hash2.toString('hex'));
```

Outputs:

```
sha256: 9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a
double sha256: 8de472e2399610baaa7f84840547cd409434e31f5d3bd71e4d947f283874f9c0
```

## Benchmarks

``` bash
$ node bench.js
crypto.sha256: ops=100000, time=0.41668067, rate=239991.93435
native.sha256: ops=100000, time=0.328309021, rate=304591.08219
crypto.hash160: ops=100000, time=0.698852504, rate=143091.71024
native.hash160: ops=100000, time=0.32359362, rate=309029.57852
crypto.hash256: ops=100000, time=0.65909456, rate=151723.29749
native.hash256: ops=100000, time=0.313477282, rate=319002.38308
crypto.sha256hmac: ops=100000, time=0.589858488, rate=169532.18786
native.sha256hmac: ops=100000, time=0.444996526, rate=224720.85546
utils.toBase58: ops=100000, time=0.808880157, rate=123627.70818
native.toBase58: ops=100000, time=0.458057275, rate=218313.31027
utils.fromBase58: ops=100000, time=0.77960898, rate=128269.43066
native.fromBase58: ops=100000, time=0.746901487, rate=133886.46527
js poly1305.update: ops=31250, time=1.6195938239999998, rate=19294.96120
js poly1305.finish: ops=31250, time=2.9935169999999998, rate=10439.22583
c poly1305.update: ops=31250, time=0.184753504, rate=169144.28860
c poly1305.finish: ops=31250, time=1.434867264, rate=21779.01802
js murmur3: ops=1000000, time=4.714874642, rate=212094.71639
c murmur3: ops=1000000, time=0.412050096, rate=2426889.37512
js siphash256: ops=1000000, time=13.218189886, rate=75653.32384
c siphash256: ops=1000000, time=1.19912212, rate=833943.41854
```

## License

Copyright (c) 2016, Christopher Jeffrey. (MIT License)

See LICENSE for more info.

[bcoin]: https://github.com/bcoin-org/bcoin
