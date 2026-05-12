import test from 'node:test';
import assert from 'node:assert/strict';

import * as smp from '../src/browser-smp-core.mjs';
import {
  createRatchetState,
  decryptRatchetMessage,
  encryptRatchetMessage
} from '../src/browser-simplex-ratchet.mjs';

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

test('ratchet encrypts decrypts and supports skipped out-of-order messages', () => {
  const aliceDh = smp.generateX25519KeyPair(filled(32, 1));
  const bobDh = smp.generateX25519KeyPair(filled(32, 2));
  const root = filled(32, 3);
  let alice = createRatchetState({ rootKey: root, ownDhKey: aliceDh, remoteDhPublicKey: bobDh.publicKey });
  let bob = createRatchetState({ rootKey: root, ownDhKey: bobDh, initializeSending: false });

  const first = encryptRatchetMessage(alice, smp.utf8Bytes('one'), { nonce: filled(24, 4) });
  alice = first.state;
  const second = encryptRatchetMessage(alice, smp.utf8Bytes('two'), { nonce: filled(24, 5) });
  alice = second.state;

  const gotSecond = decryptRatchetMessage(bob, second.packet);
  bob = gotSecond.state;
  assert.equal(smp.utf8Text(gotSecond.plaintext), 'two');
  const gotFirst = decryptRatchetMessage(bob, first.packet);
  assert.equal(smp.utf8Text(gotFirst.plaintext), 'one');
});

test('ratchet rejects tampered ciphertext', () => {
  const aliceDh = smp.generateX25519KeyPair(filled(32, 6));
  const bobDh = smp.generateX25519KeyPair(filled(32, 7));
  const root = filled(32, 8);
  const alice = createRatchetState({ rootKey: root, ownDhKey: aliceDh, remoteDhPublicKey: bobDh.publicKey });
  const bob = createRatchetState({ rootKey: root, ownDhKey: bobDh, initializeSending: false });
  const encrypted = encryptRatchetMessage(alice, smp.utf8Bytes('secret'), { nonce: filled(24, 9) });
  encrypted.packet.ciphertext[0] ^= 1;
  assert.throws(() => decryptRatchetMessage(bob, encrypted.packet), /decryption failed/i);
});
