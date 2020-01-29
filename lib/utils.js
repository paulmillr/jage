"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isBrowser = typeof window == 'object' && 'crypto' in window;
exports.labels = {
    start: 'age-encryption.org/v1',
    X25519: 'age-encryption.org/v1/X25519',
    scrypt: 'age-encryption.org/v1/scrypt',
    headerEnd: 'header',
    body: 'payload'
};
function utfToArray(str) {
    return (new TextEncoder()).encode(str);
}
exports.utfToArray = utfToArray;
function arrayToUtf(ui8a) {
    return new TextDecoder().decode(ui8a);
}
exports.arrayToUtf = arrayToUtf;
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
exports.concatArrays = concatArrays;
