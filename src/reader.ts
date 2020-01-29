import { labels, ui8a, concatArrays, utfToArray, arrayToUtf } from './utils';
import { STREAM, ChaCha20Poly1305 as chacha } from './stream';
import { HKDF, scrypt, decode } from './primitives';

const recipientTypes = {
  // -> X25519 encode(X25519(ephemeral secret, basepoint))
  // encode(encrypt[HKDF[salt, label](X25519(ephemeral secret, public key))](file key))
  X25519(encodedSecret: string, encryptedKey: string): ui8a {
  //   const labelBytes = utfToArray(labels.X25519);
  //   const secret = random(32);
  //   const secretPoint = x25519.scalarMultBase(secret);
  //   const diffieHellman = x25519.sharedKey(secret, publicKey); // or primitives.X25519?

  //   const hkdf = HKDF(secretPoint, labelBytes, diffieHellman);
  //   return `-> X25519 ${encode(secretPoint)}
  // ${encode(chacha.encrypt(hkdf, fileKey))}`;
    return new Uint8Array;
  },

  // -> scrypt encode(salt) log2(N)
  // encode(encrypt[scrypt["age-encryption.org/v1/scrypt" + salt, N](password)](file key))
  scrypt(password: ui8a, encodedSalt: string, factor: string, encodedKey: string): ui8a {
    const salt = decode(encodedSalt);
    const N = Math.pow(2, Number.parseInt(factor));
    const encryptedKey = decode(encodedKey);
    const fullLabel = concatArrays(utfToArray(labels.scrypt), salt);
    scrypt(fullLabel, N, password);
    const key = scrypt(fullLabel, N, password);
    const fileKey = chacha.decrypt(key, encryptedKey);
    return fileKey;
  },
}

function header(hdrr: ui8a) {
  // const hdr = arrayToUtf(hdrr);
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
  if (ver !== labels.start) {
    throw new Error(`only age v1 is supported for now, the file uses ${ver}`)
  }
  return {mac, recipients};
}

const NONCE_SIZE = 12;
function body(body: ui8a, fileKey: ui8a) {
  const nonce = body.slice(0, NONCE_SIZE);
  const ciphertext = body.slice(NONCE_SIZE);
  const hkdf = HKDF(nonce, utfToArray(labels.body), fileKey);
  return STREAM.open(ciphertext, hkdf);
}
