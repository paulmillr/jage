import * as x25519 from '@stablelib/x25519';
import { HKDF, HMAC, X25519, encode, scrypt, random } from './primitives';
import { ChaCha20Poly1305 as chacha, STREAM } from './stream';
import { labels, ui8a, utfToArray, arrayToUtf, concatArrays } from './utils';
const bech32 = require('bech32');

function bech32ToArray(str: string): ui8a {
  return bech32.fromWords(bech32.decode(str).words);
}

const recipientTypes = {
  // -> X25519 encode(X25519(ephemeral secret, basepoint))
  // encode(encrypt[HKDF[salt, label](X25519(ephemeral secret, public key))](file key))
  X25519(publicKey: ui8a, fileKey: ui8a): string {
    const labelBytes = utfToArray(labels.X25519);
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
    const salt = random(32);
    const fullLabel = concatArrays(utfToArray(labels.scrypt), salt);
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

type RecipientType = keyof typeof recipientTypes;
type RecipientFn = typeof recipientTypes[RecipientType];

// Example usage:
//   constructHeader(["X25519", publicKey, fileKey], ["scrypt", password, N, fileKey])
export function recipients(algorithms: any[]): string[] {
  return algorithms.map(params => {
    const type: RecipientType = params[0];
    const args: any[] = params.slice(1);
    if (!(recipientTypes.hasOwnProperty(type))) {
      return;
    }
    const generator: RecipientFn = recipientTypes[type];
    // @ts-ignore
    const text = generator(...args);
    return text;
  }).filter(t => t);
}

// File key is random data, it's encrypted with SSH key / scrypt password or so.
function getFileKey(): ui8a {
  return random(16);
}

// The header ends with the following line
// --- encode(HMAC[HKDF["", "header"](file key)](header))
// where header is the whole header up to the --- mark included. (To add a recipient, the master key
// needs to be available anyway, so it can be used to regenerate the HMAC. Removing a recipient
// without access to the key is not possible.)
function header(fileKey: ui8a, algorithms: any[]): string {
  const rec = recipients(algorithms).join('\n');
  const hdr = `${labels.start}\n${rec}`;
  const hkdf = HKDF(new Uint8Array(0), utfToArray(labels.headerEnd), fileKey);
  const hmac = HMAC(hkdf, utfToArray(hdr));
  return `${hdr}
--- ${encode(hmac)}`;
}

// After the header the binary payload is nonce || STREAM[HKDF[nonce, "payload"](file key)]
// (plaintext) where nonce is random(16) and STREAM is from Online Authenticated-Encryption and its
// Nonce-Reuse Misuse-Resistance with ChaCha20-Poly1305 in 64KiB chunks.
function body(fileKey: ui8a, plaintext: ui8a): string {
  const nonce = random(16);
  const hkdf = HKDF(nonce, utfToArray(labels.body), fileKey);
  const sealed = STREAM.seal(plaintext, hkdf);
  return `${arrayToUtf(nonce)}${arrayToUtf(sealed)}`;
}

export function encrypt(plaintext: ui8a, params: any[]): string {
  const fileKey = getFileKey();
  // TODO: pass only from getHeader.
  const hdr = header(fileKey, params);
  const bdy = body(fileKey, plaintext);
  return `${hdr}\n${bdy}`;
}

const plaintext = new Uint8Array(256);
const fileKey = new Uint8Array(32);
encrypt(plaintext, [["scrypt", utfToArray("password"), 14, fileKey]]);
