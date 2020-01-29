"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const utils_1 = require("./utils");
const stream_1 = require("./stream");
const primitives_1 = require("./primitives");
const recipientTypes = {
    X25519(encodedSecret, encryptedKey) {
        return new Uint8Array;
    },
    scrypt(password, encodedSalt, factor, encodedKey) {
        const salt = primitives_1.decode(encodedSalt);
        const N = Math.pow(2, Number.parseInt(factor));
        const encryptedKey = primitives_1.decode(encodedKey);
        const fullLabel = utils_1.concatArrays(utils_1.utfToArray(utils_1.labels.scrypt), salt);
        primitives_1.scrypt(fullLabel, N, password);
        const key = primitives_1.scrypt(fullLabel, N, password);
        const fileKey = stream_1.ChaCha20Poly1305.decrypt(key, encryptedKey);
        return fileKey;
    },
};
function header(hdrr) {
    const hdr = `age-encryption.org/v1
-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
-> X25519 8hWaIUmk67IuRZ41zMk2V9f/w3f5qUnXLL7MGPA+zE8
tXgpAxKgqyu1jl9I/ATwFgV42ZbNgeAlvCTJ0WgvfEo
-> scrypt GixTkc7+InSPLzPNGU6cFw 18
kC4zjzi7LRutdBfOlGHCgox8SXgfYxRYhWM1qPs0ca8
-> ssh-rsa SkdmSg
SW+xNSybDWTCkWx20FnCcxlfGC889s2hRxT8+giPH2DQMMFV6DyZpveqXtNwI3ts
5rVkW/7hCBSqEPQwabC6O5ls75uNjeSURwHAaIwtQ6riL9arjVpHMl8O7GWSRnx3
NltQt08ZpBAUkBqq5JKAr20t46ZinEIsD1LsDa2EnJrn0t8Truo2beGwZGkwkE2Y
j8mC2GaqR0gUcpGwIk6QZMxOdxNSOO7jhIC32nt1w2Ep1ftk9wV1sFyQo+YYrzOx
yCDdUwQAu9oM3Ez6AWkmFyG6AvKIny8I4xgJcBt1DEYZcD5PIAt51nRJQcs2/ANP
+Y1rKeTsskMHnlRpOnMlXqoeN6A3xS+EWxFTyg1GREQeaVztuhaL6DVBB22sLskw
XBHq/XlkLWkqoLrQtNOPvLoDO80TKUORVsP1y7OyUPHqUumxj9Mn/QtsZjNCPyKN
ds7P2OLD/Jxq1o1ckzG3uzv8Vb6sqYUPmRvlXyD7/s/FURA1GetBiQEdRM34xbrB
-> ssh-ed25519 Xyg06A rH24zuz7XHFc1lRyQmMrekpLrcKrJupohEh/YjvQCxs
Bbtnl6veSZhZmG7uXGQUX0hJbrC8mxDkL3zW06tqlWY
--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM`;
    let [a, mac] = hdr.split('--- ');
    let [ver, ...recpts] = a.split('-> ');
    ver = ver.trim();
    const recipients = recpts.map(r => r.replace(/\n/g, '').split(' '));
    if (ver !== utils_1.labels.start) {
        throw new Error(`only age v1 is supported for now, the file uses ${ver}`);
    }
    return { mac, recipients };
}
const NONCE_SIZE = 12;
function body(body, fileKey) {
    const nonce = body.slice(0, NONCE_SIZE);
    const ciphertext = body.slice(NONCE_SIZE);
    const hkdf = primitives_1.HKDF(nonce, utils_1.utfToArray(utils_1.labels.body), fileKey);
    return stream_1.STREAM.open(ciphertext, hkdf);
}
