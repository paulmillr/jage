export type ui8a = Uint8Array;

export const isBrowser = typeof window == 'object' && 'crypto' in window;

// Text labels used for KDF etc.
export const labels = {
  start: 'age-encryption.org/v1',
  X25519: 'age-encryption.org/v1/X25519',
  scrypt: 'age-encryption.org/v1/scrypt',
  headerEnd: 'header',
  body: 'payload'
};

// export function arrayToHex(ui8a: ui8a): string {
//   return Array.from(ui8a)
//     .map(c => c.toString(16).padStart(2, '0'))
//     .join("");
// }

export function utfToArray(str: string): ui8a {
  return (new TextEncoder()).encode(str);
}

export function arrayToUtf(ui8a: ui8a): string {
  return new TextDecoder().decode(ui8a);
}

export function concatArrays(...arrays: ui8a[]): ui8a {
  const length = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(length);
  let prevLength = 0;
  for (let arr of arrays) {
    result.set(arr, prevLength);
    prevLength += arr.length;
  }
  return result;
}
