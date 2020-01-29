import * as x25519 from '@stablelib/x25519';
import { HKDF, HMAC, X25519, encode, scrypt, random } from './primitives';
import { ChaCha20Poly1305 as chacha, STREAM } from './stream';
import { writeFileSync } from 'fs';
import * as sha256 from 'fast-sha256';
const bech32 = require('bech32');

type ui8a = Uint8Array;

function toHex(ui8a: ui8a): string {
  return Array.from(ui8a)
    .map(c => c.toString(16).padStart(2, "0"))
    .join("");
}

function bech32ToArray(str: string): ui8a {
  return bech32.fromWords(bech32.decode(str).words);
}

function utfToArray(str: string): ui8a {
  return (new TextEncoder()).encode(str);
}

function arrayToUtf(ui8a: ui8a): string {
  return new TextDecoder().decode(ui8a);
}

function concatArrays(...arrays: ui8a[]) {
  const length = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(length);
  let prevLength = 0;
  for (let arr of arrays) {
    result.set(arr, prevLength);
    prevLength += arr.length;
  }
  return result;
}

const recipientLine = {
  // -> X25519 encode(X25519(ephemeral secret, basepoint))
  // encode(encrypt[HKDF[salt, label](X25519(ephemeral secret, public key))](file key))
  X25519(publicKey: ui8a, fileKey: ui8a): string {
    const label = 'age-encryption.org/v1/X25519';
    const labelBytes = utfToArray(label);
    const secret = random(32);
    const secretPoint = x25519.scalarMultBase(secret);
    const diffieHellman = x25519.sharedKey(secret, publicKey); // or primitives.X25519?

    const hkdf = HKDF(secretPoint, labelBytes, diffieHellman);
    return `-> X25519 ${encode(secretPoint)}
  ${encode(chacha.encrypt(hkdf, fileKey))}`;
  },

  // -> scrypt encode(salt) log2(N)
  // encode(encrypt[scrypt["age-encryption.org/v1/scrypt" + salt, N](password)](file key))
  scrypt(password: ui8a, factor: number, fileKey: ui8a): string {
    const label = 'age-encryption.org/v1/scrypt/';
    const salt = random(32);
    const fullLabel = concatArrays(utfToArray(label), salt);
    const N = Math.pow(2, factor);
    const key = scrypt(fullLabel, N, password);

    return `-> scrypt ${encode(salt)} ${N}
${encode(chacha.encrypt(key, fileKey))}`;
  },

  // -> ssh-ed25519 tag encode(X25519(ephemeral secret, basepoint))
  // encode(encrypt[HKDF[salt, label](X25519(ephemeral secret, tweaked key))](file key))
  // "ssh-ed25519"(password: ui8a, fileKey: ui8a): string {
  //   const secret = random(32);
  //   // X25519(ephemeral secret, basepoint) || converted key;
  //   const salt = x25519.scalarMultBase(secret);
  //   const label = 'age-encryption.org/v1/ssh-ed25519';
  //   const ssh =
  //   const hashed = sha256.hash().slice(0, 4);
  //   const tag = encode(); // tag is encode(SHA-256(SSH key)[:4]),
  //   return "";
  // }
};

type RecipientType = keyof typeof recipientLine;
type RecipientFn = typeof recipientLine[RecipientType];

// Example usage:
//   constructHeader(["X25519", publicKey, fileKey], ["scrypt", password, N, fileKey])
function getRecipients(algorithms: any[]): string[] {
  return algorithms.map(params => {
    const type: RecipientType = params[0];
    const args: any[] = params.slice(1);
    const generator: RecipientFn = recipientLine[type];
    // @ts-ignore
    const text = generator(...args);
    return text;
  });
}

function getFileKey() {
  return random(16);
}

// The header ends with the following line
// --- encode(HMAC[HKDF["", "header"](file key)](header))
// where header is the whole header up to the --- mark included. (To add a recipient, the master key
// needs to be available anyway, so it can be used to regenerate the HMAC. Removing a recipient
// without access to the key is not possible.)
function getHeader(fileKey: ui8a, algorithms: any[]) {
  const label = 'age-encryption.org/v1';
  const headerEndLabel = 'header';
  const recipients = getRecipients(algorithms).join('\n');
  const header = `${label}\n${recipients}`;
  const hkdf = HKDF(new Uint8Array(0), utfToArray(headerEndLabel), fileKey);
  const hmac = HMAC(hkdf, utfToArray(header));
  return `${header}
--- ${encode(hmac)}`;
}

// After the header the binary payload is nonce || STREAM[HKDF[nonce, "payload"](file key)]
// (plaintext) where nonce is random(16) and STREAM is from Online Authenticated-Encryption and its
// Nonce-Reuse Misuse-Resistance with ChaCha20-Poly1305 in 64KiB chunks.
function getBody(fileKey: ui8a, plaintext: ui8a) {
  const label = 'payload';
  const nonce = random(16);
  const hkdf = HKDF(nonce, utfToArray(label), fileKey);
  const sealed = STREAM.seal(plaintext, hkdf);
  return `${arrayToUtf(nonce)}${arrayToUtf(sealed)}`;
}

export function encrypt(plaintext: ui8a) {
  const fileKey = getFileKey();
  // TODO: pass only from getHeader.
  const header = getHeader(fileKey, [["scrypt", utfToArray("password"), 14, fileKey]]);
  const body = getBody(fileKey, plaintext);
  const ageText = `${header}\n${body}`;
  return ageText;
}

export function decrypt(ageText: ui8a) {

}
