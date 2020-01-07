import cryp from 'crypto';
import * as sha256 from 'fast-sha256';
import escrypt from 'scrypt-async';
import ed25519 from 'noble-ed25519';
import * as x25519 from '@stablelib/x25519';

const isBrowser = typeof window == "object" && "crypto" in window;

// function encode(data) {
//   // TODO
//   return base64(data);
// }

function encrypt(key, plaintext) {
  // todo: browser version
  const iv = Buffer.alloc(0);
  const cipher = cryp.createCipheriv('chacha20-poly1305', key, iv, {authTagLength: 16});

  // ?
  // cipher.setAAD(aad, { plaintextLength: plaintext.length });

  const head = cipher.update(plaintext);
  const final = cipher.final();
  const ciphertext = Buffer.concat([head, final]);
  return ciphertext;
  // const tag = cipher.getAuthTag();
}

// Required: RFC 7748, including the all-zeroes output check
function X25519(secret: Uint8Array, point: Uint8Array): Uint8Array {
  return x25519.sharedKey(secret, point)
}

// 32 bytes of HKDF from RFC 5869 with SHA-256
function HKDF(salt: Uint8Array, label: Uint8Array, key: Uint8Array): Uint8Array {
  return sha256.hkdf(key, salt, label);
}

// RFC 2104 with SHA-256
function HMAC(key: Uint8Array, message: Uint8Array): Uint8Array {
  return sha256.hmac(key, message);
}

// Required: 32 bytes of scrypt from RFC 7914 with r = 8 and P = 1
function scrypt(salt: Uint8Array, N: number, password: Uint8Array): Uint8Array {
  let res: Uint8Array;
  escrypt(password, salt, {N: N, r: 8, p: 1, dkLen: 32}, key => { res = key });
  return res;
}

// Optional: RFC 8017 with SHA-256 and MGF1
// function RSAES_OAEP(key, label, plaintext) { }

// random(n) is a string of n bytes read from a CSPRNG like /dev/urandom.
function random(n: number): Uint8Array {
  if (isBrowser) {
    const array = new Uint8Array(n);
    window.crypto.getRandomValues(array);
    return array;
  } else {
    const b = cryp.randomBytes(n);
    return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  }
}
