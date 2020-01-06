const crypto  = require('crypto');
const escrypt = require('scrypt-async');
const sha256 = require('fast-sha256');

function encode(data) {
  return base64(data);
}

function encrypt(key, plaintext) {
  const iv = Buffer.alloc(0);
  // todo: browser version
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv, {authTagLength: 16});

  // ?
  // cipher.setAAD(aad, { plaintextLength: plaintext.length });

  const head = cipher.update(plaintext);
  const final = cipher.final();
  const ciphertext =  Buffer.concat([head, final]);
  return ciphertext;
  // const tag = cipher.getAuthTag();
}

// RFC 7748, including the all-zeroes output check
function X25519(secret, point) {

}

// 32 bytes of HKDF from RFC 5869 with SHA-256
function HKDF(salt, label, key) {
  return sha256.hkdf(key, salt, label);
}

// RFC 2104 with SHA-256
function HMAC(key, message) {
  return sha256.hmac(key, message);
}

// 32 bytes of scrypt from RFC 7914 with r = 8 and P = 1
function scrypt(salt, N, password) {
  let res;
  escrypt(password, salt, {N: N, r: 8, p: 1, dkLen: 32}, key => { res = key });
  return res;
}

// RFC 8017 with SHA-256 and MGF1
function RSAES_OAEP(key, label, plaintext) {

}

const isBrowser = typeof window == "object" && "crypto" in window;

// random(n) is a string of n bytes read from a CSPRNG like /dev/urandom.
function random(n) {
  if (isBrowser) {
    const array = new Uint8Array(n);
    window.crypto.getRandomValues(array);
    return array;
  } else {
    const b = crypto.randomBytes(n);
    return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  }
}
