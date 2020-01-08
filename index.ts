import * as cryp from 'crypto';
import * as sha256 from 'fast-sha256';
import * as ed25519 from 'noble-ed25519';
import * as x25519 from '@stablelib/x25519';
const bech32 = require('bech32');
const escrypt = require('scrypt-async');

const isBrowser = typeof window == "object" && "crypto" in window;

type ui8a = Uint8Array;

function toHex(ui8a: ui8a): string {
  return Array.from(ui8a)
    .map(c => c.toString(16).padStart(2, "0"))
    .join("");
}

function bech32ToArray(str: string): ui8a {
  return bech32.fromWords(bech32.decode(str).words);
}

function stringToArray(str: string): ui8a {
  return (new TextEncoder()).encode(str);
}

function concatArrays(arr1: Uint8Array, arr2: Uint8Array) {
  const result = new Uint8Array(arr1.length + arr2.length);
  result.set(arr1);
  result.set(arr2, arr1.length);
  return result;
}

const recipientLine = {
  // -> X25519 encode(X25519(ephemeral secret, basepoint))
  // encode(encrypt[HKDF[salt, label](X25519(ephemeral secret, public key))](file key))
  X25519(publicKey: ui8a, fileKey: ui8a): string {
    const label = 'age-encryption.org/v1/X25519';
    const labelBytes = stringToArray(label);
    const secret = random(32);
    const secretPoint = x25519.scalarMultBase(secret);
    const diffieHellman = x25519.sharedKey(secret, publicKey);

    const hkdf = HKDF(secretPoint, labelBytes, diffieHellman);
    return `-> X25519 ${encode(secretPoint)}
  ${encode(encrypt(hkdf, fileKey))}`;
  },

  // -> scrypt encode(salt) log2(N)
  // encode(encrypt[scrypt["age-encryption.org/v1/scrypt" + salt, N](password)](file key))
  scrypt(password: ui8a, N: number, fileKey: ui8a): string {
    const salt = random(32);
    const fullSalt = concatArrays(stringToArray(`age-encryption.org/v1/scrypt/`), salt);
    const key = scrypt(fullSalt, N, password);

    return `-> scrypt ${encode(salt)} ${N}
${encode(encrypt(key, fileKey))}`;
  }
};

function getHeader() {
  const label = `age-encryption.org/v1`;
  // const header = construct();
  // — encode(HMAC[HKDF["", "header"](file key)](header))
  const headerEnd = ``
}

function getBody(fileKey: ui8a) {
  const nonce = random(16);
  const hkdf = HKDF(nonce, stringToArray('payload'), fileKey);
}

// TODO: is this canonical?
// canonical base64 from RFC 4648 without padding.
export function encode(data: string | ui8a) {
  const buf = data instanceof Uint8Array ? Buffer.from(data) : Buffer.from(data, 'hex');
  return buf.toString('base64');
}

// ChaCha20-Poly1305 from RFC 7539 with a zero nonce.
// todo: browser version
export function encrypt(key: ui8a, plaintext: ui8a) {
  const iv = Uint8Array.from([0]);
  const cipher = cryp.createCipheriv('chacha20-poly1305', key, iv, {authTagLength: 12});

  // ?
  // cipher.setAAD(aad, { plaintextLength: plaintext.length });

  const head = cipher.update(plaintext);
  const final = cipher.final();
  const ciphertext = Buffer.concat([head, final]);
  return ciphertext;
  // const tag = cipher.getAuthTag();
}

export function decrypt(key: ui8a, ciphertext: ui8a) {
  const iv = Uint8Array.from([0]);
  const decipher = cryp.createDecipheriv('chacha20-poly1305', key, iv, {authTagLength: 12});
  const plaintext = decipher.update(ciphertext);
  const res = Buffer.concat([plaintext, decipher.final()]);
  return Uint8Array.from(res);
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
  escrypt(password, salt, {N: N, r: 8, p: 1, dkLen: 32, encoding: 'binary'}, (key: ui8a) => { res = key });
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
  const assert = require('assert');
  const key = scrypt(random(10), 16, random(10));
  const plain = random(20);
  console.log('encrypting', {key, plain});
  const cipher = encrypt(key, plain);
  const deciphered = decrypt(key, cipher);
  console.log('decrypted', {deciphered})
  assert.equal(deciphered, plain);
}
