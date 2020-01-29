"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const x25519 = require("@stablelib/x25519");
const primitives_1 = require("./primitives");
const stream_1 = require("./stream");
const bech32 = require('bech32');
function toHex(ui8a) {
    return Array.from(ui8a)
        .map(c => c.toString(16).padStart(2, "0"))
        .join("");
}
function bech32ToArray(str) {
    return bech32.fromWords(bech32.decode(str).words);
}
function utfToArray(str) {
    return (new TextEncoder()).encode(str);
}
function arrayToUtf(ui8a) {
    return new TextDecoder().decode(ui8a);
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
        const labelBytes = utfToArray(label);
        const secret = primitives_1.random(32);
        const secretPoint = x25519.scalarMultBase(secret);
        const diffieHellman = x25519.sharedKey(secret, publicKey);
        const hkdf = primitives_1.HKDF(secretPoint, labelBytes, diffieHellman);
        return `-> X25519 ${primitives_1.encode(secretPoint)}
  ${primitives_1.encode(stream_1.ChaCha20Poly1305.encrypt(hkdf, fileKey))}`;
    },
    scrypt(password, factor, fileKey) {
        const label = 'age-encryption.org/v1/scrypt/';
        const salt = primitives_1.random(32);
        const fullLabel = concatArrays(utfToArray(label), salt);
        const N = Math.pow(2, factor);
        const key = primitives_1.scrypt(fullLabel, N, password);
        return `-> scrypt ${primitives_1.encode(salt)} ${N}
${primitives_1.encode(stream_1.ChaCha20Poly1305.encrypt(key, fileKey))}`;
    },
};
function getRecipients(algorithms) {
    return algorithms.map(params => {
        const type = params[0];
        const args = params.slice(1);
        const generator = recipientLine[type];
        const text = generator(...args);
        return text;
    });
}
function getFileKey() {
    return primitives_1.random(16);
}
function getHeader(fileKey, algorithms) {
    const label = 'age-encryption.org/v1';
    const headerEndLabel = 'header';
    const recipients = getRecipients(algorithms).join('\n');
    const header = `${label}\n${recipients}`;
    const hkdf = primitives_1.HKDF(new Uint8Array(0), utfToArray(headerEndLabel), fileKey);
    const hmac = primitives_1.HMAC(hkdf, utfToArray(header));
    return `${header}
--- ${primitives_1.encode(hmac)}`;
}
function getBody(fileKey, plaintext) {
    const label = 'payload';
    const nonce = primitives_1.random(16);
    const hkdf = primitives_1.HKDF(nonce, utfToArray(label), fileKey);
    const sealed = stream_1.STREAM.seal(plaintext, hkdf);
    return `${arrayToUtf(nonce)}${arrayToUtf(sealed)}`;
}
function encrypt(plaintext) {
    const fileKey = getFileKey();
    const header = getHeader(fileKey, [["scrypt", utfToArray("password"), 14, fileKey]]);
    const body = getBody(fileKey, plaintext);
    const ageText = `${header}\n${body}`;
    return ageText;
}
exports.encrypt = encrypt;
function decrypt(ageText) {
}
exports.decrypt = decrypt;
