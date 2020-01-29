"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const x25519 = require("@stablelib/x25519");
const primitives_1 = require("./primitives");
const stream_1 = require("./stream");
const utils_1 = require("./utils");
const bech32 = require('bech32');
function bech32ToArray(str) {
    return bech32.fromWords(bech32.decode(str).words);
}
const recipientTypes = {
    X25519(publicKey, fileKey) {
        const labelBytes = utils_1.utfToArray(utils_1.labels.X25519);
        const secret = primitives_1.random(32);
        const secretPoint = x25519.scalarMultBase(secret);
        const diffieHellman = x25519.sharedKey(secret, publicKey);
        const hkdf = primitives_1.HKDF(secretPoint, labelBytes, diffieHellman);
        return `-> X25519 ${primitives_1.encode(secretPoint)}
  ${primitives_1.encode(stream_1.ChaCha20Poly1305.encrypt(hkdf, fileKey))}`;
    },
    scrypt(password, factor, fileKey) {
        const salt = primitives_1.random(32);
        const fullLabel = utils_1.concatArrays(utils_1.utfToArray(utils_1.labels.scrypt), salt);
        const N = Math.pow(2, factor);
        const key = primitives_1.scrypt(fullLabel, N, password);
        return `-> scrypt ${primitives_1.encode(salt)} ${N}
${primitives_1.encode(stream_1.ChaCha20Poly1305.encrypt(key, fileKey))}`;
    },
};
function recipients(algorithms) {
    return algorithms.map(params => {
        const type = params[0];
        const args = params.slice(1);
        if (!(recipientTypes.hasOwnProperty(type))) {
            return;
        }
        const generator = recipientTypes[type];
        const text = generator(...args);
        return text;
    }).filter(t => t);
}
exports.recipients = recipients;
function getFileKey() {
    return primitives_1.random(16);
}
function header(fileKey, algorithms) {
    const rec = recipients(algorithms).join('\n');
    const hdr = `${utils_1.labels.start}\n${rec}`;
    const hkdf = primitives_1.HKDF(new Uint8Array(0), utils_1.utfToArray(utils_1.labels.headerEnd), fileKey);
    const hmac = primitives_1.HMAC(hkdf, utils_1.utfToArray(hdr));
    return `${hdr}
--- ${primitives_1.encode(hmac)}`;
}
function body(fileKey, plaintext) {
    const nonce = primitives_1.random(16);
    const hkdf = primitives_1.HKDF(nonce, utils_1.utfToArray(utils_1.labels.body), fileKey);
    const sealed = stream_1.STREAM.seal(plaintext, hkdf);
    return `${utils_1.arrayToUtf(nonce)}${utils_1.arrayToUtf(sealed)}`;
}
function encrypt(plaintext) {
    const fileKey = getFileKey();
    const hdr = header(fileKey, [["scrypt", utils_1.utfToArray("password"), 14, fileKey]]);
    const bdy = body(fileKey, plaintext);
    return `${hdr}\n${bdy}`;
}
exports.encrypt = encrypt;
