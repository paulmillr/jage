"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const cryp = require("crypto");
const CHUNK_SIZE = 64 * 1024;
const TAG_SIZE = 12;
const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + TAG_SIZE;
const NONCE_SIZE = 11;
const LAST_BLOCK_FLAG = 1;
const COUNTER_MAX = 0xFFFFFFFFFFF0;
class STREAM {
    constructor(key) {
        this.key = key;
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
const CIPHER_NAME = 'chacha20-poly1305';
class ChaCha20Poly1305 {
    static encrypt(privateKey, plaintext, nonce) {
        const cipher = cryp.createCipheriv(CIPHER_NAME, privateKey, nonce, { authTagLength: 12 });
        const head = cipher.update(plaintext);
        const final = cipher.final();
        const auth = cipher.getAuthTag();
        const ciphertext = Buffer.concat([head, final, auth]);
        return new Uint8Array(ciphertext);
    }
    static decrypt(privateKey, ciphertext, nonce) {
        const decipher = cryp.createDecipheriv(CIPHER_NAME, privateKey, nonce, { authTagLength: 12 });
        const plaintext = decipher.update(ciphertext);
        const res = Buffer.concat([plaintext, decipher.final()]);
        return new Uint8Array(res);
    }
}
const out = STREAM.seal(new Uint8Array(22).fill(2), new Uint8Array(32).fill(1));
console.log('finished', out);
