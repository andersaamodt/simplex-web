import test from 'node:test';
import assert from 'node:assert/strict';

import * as smp from '../src/browser-smp-core.mjs';
import {
  createNativeReceivingRatchet,
  createNativeSendingRatchet,
  decryptNativeRatchetMessage,
  encodeNativeMessageHeader,
  encryptNativeRatchetMessage,
  parseNativeMessageHeader
} from '../src/browser-simplex-native-ratchet.mjs';
import { deriveNativeX3dhReceiver, deriveNativeX3dhSender } from '../src/browser-simplex-agent.mjs';

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

test('native SimpleX message headers encode X448 DH and counters', () => {
  const dh = smp.generateX448KeyPair(filled(56, 1));
  const encoded = encodeNativeMessageHeader({
    maxSupportedVersion: 2,
    dh: dh.publicKeyDer,
    previousSendCount: 3,
    messageNumber: 4
  });
  const parsed = parseNativeMessageHeader(encoded);
  assert.equal(parsed.maxSupportedVersion, 2);
  assert.equal(parsed.previousSendCount, 3);
  assert.equal(parsed.messageNumber, 4);
  assert.equal(smp.equalBytes(parsed.dh, dh.publicKey), true);
  assert.throws(() => parseNativeMessageHeader(encoded.slice(0, encoded.length - 1)), /invalid length|truncated/);
});

test('native SimpleX X448 ratchet encrypts and decrypts first messages', () => {
  const recipientX3dh1 = smp.generateX448KeyPair(filled(56, 10));
  const recipientX3dh2 = smp.generateX448KeyPair(filled(56, 11));
  const senderX3dh1 = smp.generateX448KeyPair(filled(56, 12));
  const senderX3dh2 = smp.generateX448KeyPair(filled(56, 13));
  const senderInit = deriveNativeX3dhSender({
    senderKey1: senderX3dh1,
    senderKey2: senderX3dh2,
    recipientKey1: recipientX3dh1.publicKey,
    recipientKey2: recipientX3dh2.publicKey
  });
  const receiverInit = deriveNativeX3dhReceiver({
    recipientKey1: recipientX3dh1,
    recipientKey2: recipientX3dh2,
    senderKey1: senderX3dh1.publicKey,
    senderKey2: senderX3dh2.publicKey
  });
  const senderDh = smp.generateX448KeyPair(filled(56, 14));
  const receiverDh = smp.generateX448KeyPair(filled(56, 15));
  let sender = createNativeSendingRatchet({
    init: senderInit,
    ownDhKey: senderDh,
    remoteDhPublicKey: receiverDh.publicKey
  });
  let receiver = createNativeReceivingRatchet({
    init: receiverInit,
    ownDhKey: receiverDh
  });

  const first = encryptNativeRatchetMessage(sender, smp.utf8Bytes('native hello'), {
    headerIv: filled(16, 16)
  });
  sender = first.state;
  const gotFirst = decryptNativeRatchetMessage(receiver, first.packet);
  receiver = gotFirst.state;
  assert.equal(smp.utf8Text(gotFirst.plaintext), 'native hello');
  assert.equal(gotFirst.header.messageNumber, 0);

  const second = encryptNativeRatchetMessage(sender, smp.utf8Bytes('native again'), {
    headerIv: filled(16, 18)
  });
  const gotSecond = decryptNativeRatchetMessage(receiver, second.packet);
  assert.equal(smp.utf8Text(gotSecond.plaintext), 'native again');
  assert.equal(gotSecond.header.messageNumber, 1);

  const tampered = new Uint8Array(second.packet);
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => decryptNativeRatchetMessage(receiver, tampered), /decryption failed/);
});
