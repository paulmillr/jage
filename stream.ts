// STREAM cipher
// https://eprint.iacr.org/2015/189.pdf
// There are NO js libraries right now.
// miscreant.js implements STREAM, but it doesn't support chacha
// https://github.com/miscreant/miscreant.js
//
// age spec:
// After the header the binary payload is nonce || STREAM[HKDF[nonce, "payload"](file key)](plaintext) where nonce is random(16) and STREAM is from Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance with ChaCha20-Poly1305 in 64KiB chunks and a nonce structure of 11 bytes of big endian counter, and 1 byte of last block flag (0x00 / 0x01). (The STREAM scheme is similar to the one Tink and Miscreant use, but without nonce prefix as we use HKDF, and with ChaCha20-Poly1305 instead of AES-GCM because the latter is unreasonably hard to do well or fast without hardware support.)

function STREAM(key: ui8a, plaintext: ui8a) {

}
