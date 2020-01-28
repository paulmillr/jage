"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const cryp = require("crypto");
const CHUNK_SIZE = 64 * 1024;
const TAG_SIZE = 16;
const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + TAG_SIZE;
const NONCE_SIZE = 11;
class STREAM {
    constructor(key) {
        this.key = key.slice();
        this.nonce = new Uint8Array(NONCE_SIZE + 1);
        this.nonceView = new DataView(this.nonce.buffer);
        this.counter = 0;
    }
    static seal(plaintext, privateKey) {
        const stream = new STREAM(privateKey);
        const chunks = Math.ceil(plaintext.length / CHUNK_SIZE);
        const ciphertext = new Uint8Array(plaintext.length + (chunks * TAG_SIZE));
        for (let chunk64kb = 1; chunk64kb <= chunks; chunk64kb++) {
            let start = chunk64kb - 1;
            let end = chunk64kb;
            const isLast = chunk64kb === chunks;
            const input = plaintext.slice(start * CHUNK_SIZE, end * CHUNK_SIZE);
            const output = ciphertext.subarray(start * ENCRYPTED_CHUNK_SIZE, end * ENCRYPTED_CHUNK_SIZE);
            stream.encryptChunk(input, isLast, output);
        }
        stream.clear();
        return ciphertext;
    }
    static open(ciphertext, privateKey) {
        const stream = new STREAM(privateKey);
        const chunks = Math.ceil(ciphertext.length / ENCRYPTED_CHUNK_SIZE);
        const plaintext = new Uint8Array(ciphertext.length - (chunks * TAG_SIZE));
        for (let chunk64kb = 1; chunk64kb <= chunks; chunk64kb++) {
            let start = chunk64kb - 1;
            let end = chunk64kb;
            const isLast = chunk64kb === chunks;
            const input = ciphertext.slice(start * ENCRYPTED_CHUNK_SIZE, end * ENCRYPTED_CHUNK_SIZE);
            const output = plaintext.subarray(start * CHUNK_SIZE, end * CHUNK_SIZE);
            stream.decryptChunk(input, isLast, output);
        }
        stream.clear();
        return plaintext;
    }
    encryptChunk(chunk, isLast, output) {
        if (chunk.length > CHUNK_SIZE)
            throw new Error('Chunk is too big');
        if (this.nonce[11] === 1)
            throw new Error('Last chunk has been processed');
        if (isLast)
            this.nonce[11] = 1;
        const ciphertext = ChaCha20Poly1305.encrypt(this.key, chunk, this.nonce);
        output.set(ciphertext);
        this.incrementCounter();
    }
    decryptChunk(chunk, isLast, output) {
        if (chunk.length > ENCRYPTED_CHUNK_SIZE)
            throw new Error('Chunk is too big');
        if (this.nonce[11] === 1)
            throw new Error('Last chunk has been processed');
        if (isLast)
            this.nonce[11] = 1;
        const plaintext = ChaCha20Poly1305.decrypt(this.key, chunk, this.nonce);
        output.set(plaintext);
        this.incrementCounter();
    }
    incrementCounter() {
        this.counter += 1;
        this.nonceView.setUint32(7, this.counter, false);
    }
    setCounter(value) {
        if (!Number.isSafeInteger(value))
            throw new TypeError('setCounter: invalid counter');
        if (value > Math.pow(2, 32))
            throw new Error('setCounter: Max file size is 256GB');
        const view = this.nonceView;
        view.setUint32(0, 0);
        view.setUint32(4, 0);
        view.setUint32(7, value, false);
        this.counter = value;
    }
    clear() {
        function clear(arr) {
            for (let i = 0; i < arr.length; i++) {
                arr[i] = 0;
            }
        }
        clear(this.key);
        clear(this.nonce);
        this.counter = 0;
    }
}
exports.STREAM = STREAM;
const CHACHA_NAME = 'chacha20-poly1305';
class ChaCha20Poly1305 {
    static encrypt(privateKey, plaintext, nonce = new Uint8Array(12)) {
        const cipher = cryp.createCipheriv(CHACHA_NAME, privateKey, nonce, { authTagLength: TAG_SIZE });
        const head = cipher.update(plaintext);
        const final = cipher.final();
        const tag = cipher.getAuthTag();
        const ciphertext = Buffer.concat([tag, head, final]);
        return new Uint8Array(ciphertext);
    }
    static decrypt(privateKey, ciphertext, nonce = new Uint8Array(12)) {
        const decipher = cryp.createDecipheriv(CHACHA_NAME, privateKey, nonce, { authTagLength: TAG_SIZE });
        const tag = ciphertext.slice(0, TAG_SIZE);
        decipher.setAuthTag(tag);
        const plaintext = decipher.update(ciphertext.slice(TAG_SIZE));
        const final = decipher.final();
        const res = Buffer.concat([plaintext, final]);
        return new Uint8Array(res);
    }
}
exports.ChaCha20Poly1305 = ChaCha20Poly1305;
function test() {
    const plaintext = new Uint8Array(22).fill(2);
    const key = new Uint8Array(32).fill(1);
    const sealed = STREAM.seal(plaintext, key);
    const opened = STREAM.open(sealed, key);
    console.log('finished', { plaintext, sealed, opened });
}
