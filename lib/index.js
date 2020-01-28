"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const cryp = require("crypto");
const sha256 = require("fast-sha256");
const x25519 = require("@stablelib/x25519");
const stream_1 = require("./stream");
const bech32 = require('bech32');
const escrypt = require('scrypt-async');
const isBrowser = typeof window == "object" && "crypto" in window;
const { encrypt, decrypt } = stream_1.ChaCha20Poly1305;
function toHex(ui8a) {
    return Array.from(ui8a)
        .map(c => c.toString(16).padStart(2, "0"))
        .join("");
}
function bech32ToArray(str) {
    return bech32.fromWords(bech32.decode(str).words);
}
function stringToArray(str) {
    return (new TextEncoder()).encode(str);
}
function concatArrays(...arrays) {
    const length = arrays.reduce((sum, a) => sum + a.length, 0);
    const result = new Uint8Array(length);
    let prevLength = 0;
    for (let arr of arrays) {
        result.set(arr, prevLength);
        prevLength += arr.length;
    }
    return result;
}
const recipientLine = {
    X25519(publicKey, fileKey) {
        const label = 'age-encryption.org/v1/X25519';
        const labelBytes = stringToArray(label);
        const secret = random(32);
        const secretPoint = x25519.scalarMultBase(secret);
        const diffieHellman = x25519.sharedKey(secret, publicKey);
        const hkdf = HKDF(secretPoint, labelBytes, diffieHellman);
        return `-> X25519 ${encode(secretPoint)}
  ${encode(encrypt(hkdf, fileKey))}`;
    },
    scrypt(password, N, fileKey) {
        const salt = random(32);
        const fullSalt = concatArrays(stringToArray(`age-encryption.org/v1/scrypt/`), salt);
        const key = scrypt(fullSalt, N, password);
        return `-> scrypt ${encode(salt)} ${N}
${encode(encrypt(key, fileKey))}`;
    }
};
function getHeader() {
    const label = `age-encryption.org/v1`;
    const headerEnd = ``;
}
function getBody(fileKey, plaintext) {
    const nonce = random(16);
    const hkdf = HKDF(nonce, stringToArray('payload'), fileKey);
    const sealed = stream_1.STREAM.seal(plaintext, hkdf);
    const body = concatArrays(nonce, sealed);
    return body;
}
function encode(data) {
    const buf = data instanceof Uint8Array ? Buffer.from(data) : Buffer.from(data, 'hex');
    return buf.toString('base64');
}
exports.encode = encode;
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
    escrypt(password, salt, { N: N, r: 8, p: 1, dkLen: 32, encoding: 'binary' }, (key) => { res = key; });
    return res;
}
exports.scrypt = scrypt;
function random(n) {
    if (isBrowser) {
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
    const assert = require('assert');
    const key = scrypt(random(10), 16, random(10));
    const plain = random(20);
    console.log('encrypting', { key, plain });
    const cipher = encrypt(key, plain);
    const deciphered = decrypt(key, cipher);
    console.log('decrypted', { deciphered });
    assert.equal(deciphered, plain);
}
