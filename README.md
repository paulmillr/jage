# jage - age in JS

[age-encryption.org](https://age-encryption.org) tool implementation in JavaScript.

## Spec

See the latest spec at https://gist.github.com/paulmillr/9c80bb176ee039272ab5c915d3c73afc.

tl;dr:

- `encode(data)` is ~canonical~ base64 from RFC 4648 without padding.
- `encrypt[key](plaintext)` is ChaCha20-Poly1305 from RFC 7539 with a zero nonce.
- `X25519(secret, point)` is from RFC 7748, including the all-zeroes output check.
- `HKDF[salt, label](key)` is 32 bytes of HKDF from RFC 5869 with SHA-256.
- `HMAC[key](message)` is HMAC from RFC 2104 with SHA-256.
- `scrypt[salt, N](password)` is 32 bytes of scrypt from RFC 7914  [with r = 8 and P = 1](https://blog.filippo.io/the-scrypt-parameters/) .
- `RSAES-OAEP[key, label](plaintext)` is from RFC 8017 with SHA-256 and MGF1.
- `random(n)` is a string of n bytes read from a CSPRNG like /dev/urandom.

## Usage

```sh
$ age-keygen > key.txt

$ cat key.txt
## created: 2006-01-02T15:04:05Z07:00
## public key: age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5
AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS

$ echo "_o/" | age -r age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5 -o hello.age

$ age -decrypt -i key.txt hello.age
_o/

$ tar cv ~/xxx | age -r github:Benjojo -r github:FiloSottile | nc 192.0.2.0 1234
```

## License

MIT License, see LICENSE file.