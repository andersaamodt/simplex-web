import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import * as smp from '../src/browser-smp-core.mjs';
import * as agent from '../src/browser-simplex-agent.mjs';

const FUZZ_SEED = 0x46554c4c;

function bytes(values) {
  return new Uint8Array(values);
}

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

test('client message headers encode confirmation and empty private-header shapes', () => {
  const senderSign = smp.generateEd25519KeyPair(filled(32, 1));
  const confirmation = agent.parseClientMessage(agent.encodeClientMessage({
    privateHeader: {
      type: 'confirmation',
      senderPublicVerifyKey: senderSign.publicKeyDer
    },
    body: smp.utf8Bytes('profile')
  }));
  assert.equal(confirmation.header.type, 'confirmation');
  assert.equal(smp.equalBytes(confirmation.header.senderPublicVerifyKey, senderSign.publicKeyDer), true);
  assert.equal(smp.utf8Text(confirmation.body), 'profile');

  const empty = agent.parseClientMessage(agent.encodeClientMessage({
    privateHeader: { type: 'empty' },
    body: smp.utf8Bytes('message')
  }));
  assert.deepEqual(empty.header, { type: 'empty' });
  assert.equal(smp.utf8Text(empty.body), 'message');

  assert.throws(() => agent.parseClientMessage(bytes([0xff, 1, 2])), /private header tag/);
});

test('client message envelope encrypts and decrypts confirmation bodies', () => {
  const alice = smp.generateX25519KeyPair(filled(32, 2));
  const bob = smp.generateX25519KeyPair(filled(32, 3));
  const sharedBySender = smp.x25519SharedSecret(bob.secretKey, alice.publicKey);
  const sharedByRecipient = smp.x25519SharedSecret(alice.secretKey, bob.publicKey);
  const senderSign = smp.generateEd25519KeyPair(filled(32, 4));

  const envelope = agent.encryptClientMessage({
    sharedSecret: sharedBySender,
    nonce: filled(24, 5),
    publicHeader: {
      version: 1,
      e2ePubDhKey: bob.publicKeyDer
    },
    privateHeader: {
      type: 'confirmation',
      senderPublicVerifyKey: senderSign.publicKeyDer
    },
    body: smp.utf8Bytes('hello from browser')
  });

  const decrypted = agent.decryptClientMessageEnvelope({
    sharedSecret: sharedByRecipient,
    envelope
  });

  assert.equal(decrypted.publicHeader.version, 1);
  assert.equal(smp.equalBytes(decrypted.publicHeader.e2ePubDhKey, bob.publicKeyDer), true);
  assert.equal(decrypted.privateHeader.type, 'confirmation');
  assert.equal(smp.equalBytes(decrypted.privateHeader.senderPublicVerifyKey, senderSign.publicKeyDer), true);
  assert.equal(smp.utf8Text(decrypted.body), 'hello from browser');

  const tampered = new Uint8Array(envelope);
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => agent.decryptClientMessageEnvelope({ sharedSecret: sharedByRecipient, envelope: tampered }), /decryption failed/);
});

test('received message body decrypts server metadata and encrypted client envelope', () => {
  const serverSecret = filled(32, 6);
  const msgId = filled(24, 7);
  const envelope = smp.utf8Bytes('encrypted-client-envelope-placeholder');
  const encryptedBody = agent.encryptRcvMessageBody({
    serverDhSecret: serverSecret,
    msgId,
    timestamp: 1770000000,
    flags: { notification: true },
    body: envelope
  });

  const decrypted = agent.decryptRcvMessageBody({
    serverDhSecret: serverSecret,
    msgId,
    encryptedBody
  });

  assert.equal(decrypted.timestamp, 1770000000n);
  assert.deepEqual(decrypted.flags, { notification: true });
  assert.equal(smp.equalBytes(decrypted.body, envelope), true);
  assert.throws(() => agent.decryptRcvMessageBody({
    serverDhSecret: filled(32, 8),
    msgId,
    encryptedBody
  }), /decryption failed/);
});

test('new queue request signs NEW and derives queue state from IDS', () => {
  const sessionId = filled(32, 9);
  const request = agent.prepareNewQueueRequest({
    version: 4,
    sessionId,
    corrId: smp.asciiBytes('new-1'),
    server: { scheme: 'smp', host: 'smp.example.net', port: '5223', keyHash: filled(32, 10) },
    rcvSignSeed: filled(32, 11),
    rcvDhSeed: filled(32, 12)
  });
  const inspected = agent.inspectSignedCommand(4, request.transmission);
  assert.equal(inspected.command.type, 'NEW');
  assert.equal(inspected.queueId.length, 0);
  assert.equal(smp.ed25519Verify(request.rcvSignKey.publicKey, inspected.signed, inspected.signature), true);

  const serverDh = smp.generateX25519KeyPair(filled(32, 13));
  const ids = smp.parseBrokerMessage(4, smp.encodeBrokerMessage(4, {
    type: 'IDS',
    rcvId: filled(24, 14),
    sndId: filled(24, 15),
    rcvPublicDhKey: serverDh.publicKeyDer
  }));
  const queue = agent.completeNewQueueRequest(request, ids);
  assert.equal(smp.equalBytes(queue.rcvId, filled(24, 14)), true);
  assert.equal(smp.equalBytes(queue.sndId, filled(24, 15)), true);
  assert.equal(smp.equalBytes(queue.serverDhSecret, smp.x25519SharedSecret(serverDh.secretKey, request.rcvDhKey.publicKey)), true);
  assert.deepEqual(agent.queueSummary(queue), {
    hasServer: true,
    rcvIdLength: 24,
    sndIdLength: 24,
    hasRecipientSigningKey: true,
    hasRecipientDhSecret: true
  });
});

test('recipient commands sign queue-scoped SUB and ACK transmissions', () => {
  const request = agent.prepareNewQueueRequest({
    sessionId: filled(32, 16),
    corrId: smp.asciiBytes('new-2'),
    rcvSignSeed: filled(32, 17),
    rcvDhSeed: filled(32, 18)
  });
  const serverDh = smp.generateX25519KeyPair(filled(32, 19));
  const queue = agent.completeNewQueueRequest(request, {
    type: 'IDS',
    rcvId: filled(24, 20),
    sndId: filled(24, 21),
    rcvPublicDhKey: serverDh.publicKeyDer
  });

  const sub = agent.inspectSignedCommand(4, agent.prepareRecipientCommand(queue, {
    sessionId: filled(32, 22),
    corrId: smp.asciiBytes('sub-1'),
    command: { type: 'SUB' }
  }));
  assert.equal(sub.command.type, 'SUB');
  assert.equal(smp.equalBytes(sub.queueId, queue.rcvId), true);
  assert.equal(smp.ed25519Verify(queue.rcvSignKey.publicKey, sub.signed, sub.signature), true);

  const ack = agent.inspectSignedCommand(4, agent.prepareRecipientCommand(queue, {
    sessionId: filled(32, 22),
    corrId: smp.asciiBytes('ack-1'),
    command: { type: 'ACK', msgId: filled(24, 23) }
  }));
  assert.equal(ack.command.type, 'ACK');
  assert.equal(smp.equalBytes(ack.command.msgId, filled(24, 23)), true);
  assert.equal(smp.ed25519Verify(queue.rcvSignKey.publicKey, ack.signed, ack.signature), true);
});

test('initial sender message is unsigned at SMP level but carries confirmation key inside E2E envelope', () => {
  const recipientE2e = smp.generateX25519KeyPair(filled(32, 24));
  const senderE2e = smp.generateX25519KeyPair(filled(32, 25));
  const sharedBySender = smp.x25519SharedSecret(senderE2e.secretKey, recipientE2e.publicKey);
  const sharedByRecipient = smp.x25519SharedSecret(recipientE2e.secretKey, senderE2e.publicKey);

  const prepared = agent.prepareInitialSenderMessage({
    version: 4,
    sessionId: filled(32, 26),
    corrId: smp.asciiBytes('confirm-1'),
    senderQueueId: filled(24, 27),
    senderSignSeed: filled(32, 28),
    e2eSharedSecret: sharedBySender,
    senderE2ePubDhKey: senderE2e.publicKeyDer,
    nonce: filled(24, 29),
    body: smp.utf8Bytes('browser profile payload')
  });
  const inspected = agent.inspectSignedCommand(4, prepared.transmission);
  assert.equal(inspected.command.type, 'SEND');
  assert.equal(inspected.signature.length, 0);
  assert.equal(smp.equalBytes(inspected.queueId, filled(24, 27)), true);

  const decrypted = agent.decryptClientMessageEnvelope({
    sharedSecret: sharedByRecipient,
    envelope: inspected.command.body
  });
  assert.equal(decrypted.privateHeader.type, 'confirmation');
  assert.equal(smp.equalBytes(decrypted.privateHeader.senderPublicVerifyKey, prepared.senderSignKey.publicKeyDer), true);
  assert.equal(smp.utf8Text(decrypted.body), 'browser profile payload');
});

test('message id nonce follows SimpleX truncate and zero-pad behavior', () => {
  assert.equal(smp.equalBytes(agent.messageIdNonce(bytes([1, 2, 3])).slice(0, 3), bytes([1, 2, 3])), true);
  assert.equal(agent.messageIdNonce(bytes([1, 2, 3])).length, 24);
  assert.equal(smp.equalBytes(agent.messageIdNonce(filled(40, 9)), filled(24, 9)), true);
});

test('native SimpleX X3DH sender and receiver derive the same initial ratchet keys', () => {
  const recipientKey1 = smp.generateX448KeyPair(filled(56, 40));
  const recipientKey2 = smp.generateX448KeyPair(filled(56, 41));
  const senderKey1 = smp.generateX448KeyPair(filled(56, 42));
  const senderKey2 = smp.generateX448KeyPair(filled(56, 43));

  const sender = agent.deriveNativeX3dhSender({
    senderKey1,
    senderKey2,
    recipientKey1: smp.decodePublicKeyDer(recipientKey1.publicKeyDer),
    recipientKey2: smp.decodePublicKeyDer(recipientKey2.publicKeyDer)
  });
  const receiver = agent.deriveNativeX3dhReceiver({
    recipientKey1,
    recipientKey2,
    senderKey1: senderKey1.publicKeyDer,
    senderKey2: senderKey2.publicKeyDer
  });

  assert.equal(smp.equalBytes(sender.associatedData, receiver.associatedData), true);
  assert.equal(smp.equalBytes(sender.ratchetKey, receiver.ratchetKey), true);
  assert.equal(smp.equalBytes(sender.sendHeaderKey, receiver.sendHeaderKey), true);
  assert.equal(smp.equalBytes(sender.receiveNextHeaderKey, receiver.receiveNextHeaderKey), true);
  assert.equal(sender.ratchetKey.length, 32);
  assert.equal(sender.sendHeaderKey.length, 32);
  assert.equal(sender.receiveNextHeaderKey.length, 32);
  assert.throws(
    () => agent.deriveNativeX3dhSender({
      senderKey1,
      senderKey2,
      recipientKey1: smp.generateX25519KeyPair(filled(32, 44)).publicKey,
      recipientKey2: recipientKey2.publicKey
    }),
    /X448/
  );
});

test('agent envelope fuzzing preserves hostile binary bodies without changing header state', () => {
  fc.assert(fc.property(
    fc.uint8Array({ minLength: 0, maxLength: 512 }),
    fc.boolean(),
    (body, includePublicKey) => {
      const alice = smp.generateX25519KeyPair(filled(32, 30));
      const bob = smp.generateX25519KeyPair(filled(32, 31));
      const shared = smp.x25519SharedSecret(alice.secretKey, bob.publicKey);
      const envelope = agent.encryptClientMessage({
        sharedSecret: shared,
        nonce: filled(24, 32),
        publicHeader: {
          version: 1,
          e2ePubDhKey: includePublicKey ? bob.publicKeyDer : null
        },
        privateHeader: { type: 'empty' },
        body
      });
      const decrypted = agent.decryptClientMessageEnvelope({ sharedSecret: shared, envelope });
      assert.equal(decrypted.privateHeader.type, 'empty');
      assert.equal(!!decrypted.publicHeader.e2ePubDhKey, includePublicKey);
      assert.equal(smp.equalBytes(decrypted.body, body), true);
    }
  ), { seed: FUZZ_SEED, numRuns: 100 });
});
