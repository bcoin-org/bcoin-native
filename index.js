/*!
 * bcoin-native
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin-native
 */

'use strict';

var bcn = require('bindings')('bcoin-native');
var crypto;

/*
 * Load crypto.
 */

bcn.hash = function hash(alg, data) {
  if (!crypto)
    crypto = require('crypto');
  return bcn._hash(alg, data);
};

bcn.hmac = function hmac(alg, data, key) {
  if (!crypto)
    crypto = require('crypto');
  return bcn._hmac(alg, data, key);
};

/*
 * Promisify some functions.
 */

bcn.scryptAsync = function scryptAsync(passwd, salt, N, r, p, len) {
  return new Promise(function(resolve, reject) {
    bcn._scryptAsync(passwd, salt, N, r, p, len, wrap(resolve, reject));
  });
};

/*
 * Helpers
 */

function wrap(resolve, reject) {
  return function(err, result) {
    if (err) {
      reject(err);
      return;
    }
    resolve(result);
  };
}

/*
 * Expose
 */

module.exports = bcn;
