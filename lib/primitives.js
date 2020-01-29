"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const cryp = require("crypto");
const sha256 = require("fast-sha256");
const x25519 = require("@stablelib/x25519");
const utils_1 = require("./utils");
const escrypt = require('scrypt-async');
function encode(data) {
    const bytes = data instanceof Uint8Array ? Buffer.from(data) : Buffer.from(data, 'hex');
    let str = bytes.toString('base64');
    while (str.length && str[str.length - 1] === '=') {
        str = str.slice(0, -1);
    }
    return str;
}
exports.encode = encode;
function decode(data) {
    const bytes = data instanceof Uint8Array ? Buffer.from(data) : Buffer.from(data, 'hex');
    return new Uint8Array();
}
exports.decode = decode;
function X25519(secret, point) {
    return x25519.sharedKey(secret, point, true);
}
exports.X25519 = X25519;
function HKDF(salt, label, key) {
    return sha256.hkdf(key, salt, label);
}
exports.HKDF = HKDF;
function HMAC(key, message) {
    return sha256.hmac(key, message);
}
exports.HMAC = HMAC;
function scrypt(salt, N, password) {
    let res = undefined;
    escrypt(password, salt, { N: N, r: 8, p: 1, dkLen: 32, encoding: 'binary' }, (key) => {
        res = key;
    });
    return res;
}
exports.scrypt = scrypt;
function random(n) {
    if (utils_1.isBrowser) {
        const array = new Uint8Array(n);
        window.crypto.getRandomValues(array);
        return array;
    }
    else {
        const b = cryp.randomBytes(n);
        return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    }
}
exports.random = random;
function testEncryptDecrypt() {
}
