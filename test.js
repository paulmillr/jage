const bech32 = require('bech32');
const x25519 = require('@stablelib/x25519');
const assert = require('assert');

function toHex(ui8a) {
  return Buffer.from(ui8a).toString('hex');
}

function bech32ToArray(str) {
  return bech32.fromWords(bech32.decode(str).words);
}

const keys = {
  hex: {
    priv: '44bf5e711b2ca64d26dae9fc0cf08e4c7f93daa0e9c825f5a36280f8b457b60e',
    pub: 'aacdeb4256375ced09b2ab202304ddb3f82254d6ee0c95c34449582ceb107d14'
  },

  bech: {
    priv: 'AGE-SECRET-KEY-1GJL4UUGM9JNY6FK6A87QEUYWF3LE8K4QA8YZTADRV2Q03DZHKC8QMDJUPT',
    pub: 'age14tx7ksjkxaww6zdj4vszxpxak0uzy4xkacxfts6yf9vze6cs052qxpk252'
  }
};

function testBech32Decryption() {
  const priv = bech32ToArray(keys.bech.priv);
  const pub = bech32ToArray(keys.bech.pub);
  assert.equal(toHex(x25519.scalarMultBase(priv)), keys.hex.pub);
}

