# jage - age in JS

[age-encryption.org](https://age-encryption.org) tool implementation in JavaScript.

See the latest spec at https://gist.github.com/paulmillr/9c80bb176ee039272ab5c915d3c73afc.

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