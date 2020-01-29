import * as cryp from 'crypto';
import * as sha256 from 'fast-sha256';
import * as ed25519 from 'noble-ed25519';
import * as x25519 from '@stablelib/x25519';
const escrypt = require('scrypt-async');

type ui8a = Uint8Array;

const isBrowser = typeof window == "object" && "crypto" in window;

function trimBase64Padding(str: string): string {
  while (str.length && str[str.length - 1] === '=') {
    str = str.slice(0, -1);
  }
  return str;
}

function base64(bytes: Buffer): string {
  const str = bytes.toString('base64');
  return trimBase64Padding(str);
}


// canonical base64 (base64url) from RFC 4648 without padding.
export function encode(data: string | ui8a) {
  const buf = data instanceof Uint8Array ? Buffer.from(data) : Buffer.from(data, 'hex');
  return base64(buf);
}

// Required: RFC 7748, including the all-zeroes output check
export function X25519(secret: ui8a, point: ui8a): ui8a {
  return x25519.sharedKey(secret, point, true);
}

// 32 bytes of HKDF from RFC 5869 with SHA-256
export function HKDF(salt: ui8a, label: ui8a, key: ui8a): ui8a {
  return sha256.hkdf(key, salt, label);
}

// RFC 2104 with SHA-256
export function HMAC(key: ui8a, message: ui8a): ui8a {
  return sha256.hmac(key, message);
}

// Required: 32 bytes of scrypt from RFC 7914 with r = 8 and P = 1
export function scrypt(salt: ui8a, N: number, password: ui8a): ui8a {
  let res: ui8a = undefined as any;
  escrypt(password, salt, {N: N, r: 8, p: 1, dkLen: 32, encoding: 'binary'}, (key: ui8a) => {
    res = key
  });
  return res;
}

// Optional: RFC 8017 with SHA-256 and MGF1
// function RSAES_OAEP(key, label, plaintext) { }

// random(n) is a string of n bytes read from a CSPRNG like /dev/urandom.
export function random(n: number): ui8a {
  if (isBrowser) {
    const array = new Uint8Array(n);
    window.crypto.getRandomValues(array);
    return array;
  } else {
    const b = cryp.randomBytes(n);
    return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  }
}

function testEncryptDecrypt() {
  // const assert = require('assert');
  // const key = scrypt(random(10), 16, random(10));
  // const plain = random(20);
  // console.log('encrypting', {key, plain});
  // const cipher = encrypt(key, plain);
  // const deciphered = decrypt(key, cipher);
  // console.log('decrypted', {deciphered})
  // assert.equal(deciphered, plain);
}
