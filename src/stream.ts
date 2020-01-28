// STREAM cipher
// https://eprint.iacr.org/2015/189.pdf
// There are NO js libraries right now.
// miscreant.js implements STREAM, but it doesn't support chacha
// https://github.com/miscreant/miscreant.js
//
// age spec:
// After the header the binary payload is nonce || STREAM[HKDF[nonce, "payload"](file key)](plaintext) where nonce is random(16) and STREAM is from Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance with ChaCha20-Poly1305 in 64KiB chunks and a nonce structure of 11 bytes of big endian counter, and 1 byte of last block flag (0x00 / 0x01). (The STREAM scheme is similar to the one Tink and Miscreant use, but without nonce prefix as we use HKDF, and with ChaCha20-Poly1305 instead of AES-GCM because the latter is unreasonably hard to do well or fast without hardware support.)

import * as cryp from 'crypto';
// ChaCha20-Poly1305 from RFC 7539 with a zero nonce.
// todo: browser version

const CHUNK_SIZE = 64 * 1024; // 64 KiB
const TAG_SIZE = 12;
const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + TAG_SIZE;
const NONCE_SIZE = 11; /** Size of a nonce required by STREAM in bytes + last block */
const LAST_BLOCK_FLAG = 1; /** Byte flag: last block in the STREAM? yes=1, no=0 */
const COUNTER_MAX = 0xFFFFFFFFFFF0; /** Max value of the counter STREAM uses internally to identify messages */

export interface IAEADLike {
  seal(plaintext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array): Promise<Uint8Array>;
  open(ciphertext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array): Promise<Uint8Array>;
  clear(): this;
}

type ui8a = Uint8Array;

class STREAM {
  static seal(plaintext: ui8a, privateKey: ui8a) {
    // const plaintext = new Uint8Array(128 * 1024);
    // const privateKey = new Uint8Array(32);
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

  key: ui8a;
  nonce: ui8a;
  nonceView: DataView;
  counter: number;
  constructor(key: ui8a) {
    this.key = key;
    this.nonce = new Uint8Array(NONCE_SIZE + 1);
    this.nonceView = new DataView(this.nonce.buffer);
    this.counter = 0;
  }

  encryptChunk(chunk: ui8a, isLast: boolean, output: ui8a) {
    if (chunk.length > CHUNK_SIZE) throw new Error('Chunk is too big');
    if (this.nonce[11] === 1) throw new Error('Last chunk has been processed');
    if (isLast) this.nonce[11] = 1;
    const ciphertext = ChaCha20Poly1305.encrypt(this.key, chunk, this.nonce);
    output.set(ciphertext);
    this.incrementCounter();
  }

  decryptChunk(chunk: ui8a, isLast: boolean, output: ui8a) {
    if (chunk.length > ENCRYPTED_CHUNK_SIZE) throw new Error('Chunk is too big');
    if (this.nonce[11] === 1) throw new Error('Last chunk has been processed');
    if (isLast) this.nonce[11] = 1;
    const plaintext = ChaCha20Poly1305.decrypt(this.key, chunk, this.nonce);
    output.set(plaintext);
    this.incrementCounter();
  }

  // Increments Big Endian Uint8Array-based counter.
  // [0, 0, 0] => [0, 0, 1] ... => [0, 0, 255] => [0, 1, 0]
  incrementCounter() {
    this.counter += 1;
    this.nonceView.setUint32(7, this.counter, false);
    // for (let i = 10; i >= 0; i--) {
    //   ui8a[i] = ui8a[i] + 1;
    //   if (ui8a[i] === 0) {
    //     if (i === 0) throw new Error('Nonce overflow');
    //     continue;
    //   } else {
    //     break;
    //   }
    // }
    // return ui8a;
  }

  setCounter(value: number) {
    if (!Number.isSafeInteger(value)) throw new TypeError('setCounter: invalid counter');
    if (value > Math.pow(2, 32)) throw new Error('setCounter: Max file size is 256GB');
    const view = this.nonceView;
    view.setUint32(0, 0);
    view.setUint32(4, 0);
    view.setUint32(7, value, false);
    this.counter = value;
  }

  clear() {
    function clear(arr: Uint8Array) {
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
  static encrypt(privateKey: ui8a, plaintext: ui8a, nonce: ui8a): ui8a {
    const cipher = cryp.createCipheriv(CIPHER_NAME, privateKey, nonce, {authTagLength: 12});
    // if (associatedData) cipher.setAAD(associatedData, {plaintextLength: plaintext.length});
    const head = cipher.update(plaintext);
    const final = cipher.final();
    const auth = cipher.getAuthTag();
    const ciphertext = Buffer.concat([head, final, auth]);
    // console.log(123, new Uint8Array(ciphertext))
    // console.log(123, ciphertext, ciphertext.buffer, new Uint8Array(ciphertext.buffer));
    return new Uint8Array(ciphertext);
  }

  static decrypt(privateKey: ui8a, ciphertext: ui8a, nonce: ui8a): ui8a {
    const decipher = cryp.createDecipheriv(CIPHER_NAME, privateKey, nonce, {authTagLength: 12});
    // if (associatedData) decipher.setAAD(associatedData);
    const plaintext = decipher.update(ciphertext);
    const res = Buffer.concat([plaintext, decipher.final()]);
    return new Uint8Array(res);
  }
}

const out = STREAM.seal(new Uint8Array(22).fill(2), new Uint8Array(32).fill(1));
console.log('finished', out);
