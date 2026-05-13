import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import * as smp from '../src/browser-smp-core.mjs';

const FUZZ_SEED = 0x5a6d7057;

function bytes(values) {
  return new Uint8Array(values);
}

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

test('SMP queue URI parser round-trips strict server identity and queue data', () => {
  const keyHash = filled(32, 1);
  const queueId = filled(24, 2);
  const recipientDh = smp.generateX25519KeyPair(filled(32, 3)).publicKeyDer;
  const uri = smp.formatSmpQueueUri({
    server: { scheme: 'smp', keyHash, host: 'smp.example.net', port: '5223' },
    queueId,
    recipientDhPublicKey: recipientDh
  });

  assert.equal(uri.startsWith('smp://'), true);
  const parsed = smp.parseSmpQueueUri(uri);
  assert.equal(parsed.server.scheme, 'smp');
  assert.equal(parsed.server.host, 'smp.example.net');
  assert.equal(parsed.server.port, '5223');
  assert.equal(smp.equalBytes(parsed.server.keyHash, keyHash), true);
  assert.equal(smp.equalBytes(parsed.queueId, queueId), true);
  assert.equal(smp.equalBytes(parsed.recipientDhPublicKey, recipientDh), true);
});

test('SMP queue URI parser rejects command, whitespace, and path-shaped input', () => {
  assert.throws(() => smp.parseSmpQueueUri('https://example.test'), /recipient key fragment/);
  assert.throws(() => smp.parseSmpQueueUri('smp://abc@smp.example/a/b#Yw'), /exactly one queue path/);
  assert.throws(() => smp.parseSmpQueueUri('smp://abc@smp.example/q#bad+base64'), /base64url/);
  assert.throws(() => smp.parseSmpQueueUri('smp://abc@smp.example/q#key\nforged=1'), /control or whitespace/);
  assert.throws(() => smp.parseProtocolServer('smp://abc@../5223'), /protocol server/);
});

test('SimpleX connection link parser separates browser queue and native agent invitations', () => {
  const server = { scheme: 'smp', keyHash: filled(32, 10), host: 'smp.example.net', port: '5223' };
  const queueId = filled(24, 11);
  const recipientDh = smp.generateX25519KeyPair(filled(32, 12)).publicKeyDer;
  const browserQueueUri = smp.formatSmpQueueUri({ server, queueId, recipientDhPublicKey: recipientDh });
  const browserLink = smp.parseSimplexConnectionLink(browserQueueUri);

  assert.equal(browserLink.browserProfile, true);
  assert.equal(browserLink.nativeAgentProfile, false);
  assert.equal(browserLink.queueUri, browserQueueUri);

  const nativeQueue = smp.formatProtocolServer(server) + '/' + smp.encodeBase64Url(queueId) +
    '#/?v=1-4&dh=' + encodeURIComponent(smp.encodeBase64Url(recipientDh)) + '&q=m&k=s&srv=onion.example';
  const nativeLink = 'simplex:/invitation#/?v=2-7&smp=' + encodeURIComponent(nativeQueue) +
    '&e2e=' + encodeURIComponent('v=2-3&x3dh=native-key-material');
  const parsedNative = smp.parseSimplexConnectionLink(nativeLink);

  assert.equal(parsedNative.scheme, 'simplex');
  assert.equal(parsedNative.type, 'invitation');
  assert.equal(parsedNative.browserProfile, false);
  assert.equal(parsedNative.nativeAgentProfile, true);
  assert.equal(parsedNative.queueUri, browserQueueUri);
  assert.equal(parsedNative.smpQueues[0].native.queueMode, 'm');
  assert.equal(parsedNative.smpQueues[0].native.onionHost, 'onion.example');
});

test('SimpleX connection link parser rejects hostile native link wrappers', () => {
  assert.throws(() => smp.parseSimplexConnectionLink('simplex:/invitation#/?v=2-7'), /missing SMP/);
  assert.throws(() => smp.parseSimplexConnectionLink('simplex:/invitation#/?smp=smp%3A%2F%2Fa%40host%2Fq%23%2F%3Fv%3D1-4'), /missing recipient DH/);
  assert.throws(() => smp.parseSimplexConnectionLink('simplex:/unsupported#/?smp=x'), /type is unsupported/);
  assert.throws(() => smp.parseSimplexConnectionLink('simplex:/invitation#/?smp=x%0Aforged%3D1'), /control or whitespace|protocol server|recipient key/);
});

test('command codecs encode and parse core recipient and sender operations', () => {
  const rcvSign = smp.generateEd25519KeyPair(filled(32, 4));
  const rcvDh = smp.generateX25519KeyPair(filled(32, 5));
  const sndSign = smp.generateEd25519KeyPair(filled(32, 6));
  const msgBody = bytes([9, 8, 7, 6]);

  const newCommand = smp.encodeCommand(4, {
    type: 'NEW',
    rcvPublicVerifyKey: rcvSign.publicKeyDer,
    rcvPublicDhKey: rcvDh.publicKeyDer
  });
  const parsedNew = smp.parseCommand(4, newCommand);
  assert.equal(parsedNew.type, 'NEW');
  assert.equal(smp.equalBytes(parsedNew.rcvPublicVerifyKey, rcvSign.publicKeyDer), true);
  assert.equal(smp.equalBytes(parsedNew.rcvPublicDhKey, rcvDh.publicKeyDer), true);

  const parsedKey = smp.parseCommand(4, smp.encodeCommand(4, {
    type: 'KEY',
    sndPublicVerifyKey: sndSign.publicKeyDer
  }));
  assert.equal(parsedKey.type, 'KEY');
  assert.equal(smp.equalBytes(parsedKey.sndPublicVerifyKey, sndSign.publicKeyDer), true);

  const parsedSend = smp.parseCommand(4, smp.encodeCommand(4, {
    type: 'SEND',
    flags: { notification: true },
    body: msgBody
  }));
  assert.deepEqual(parsedSend.flags, { notification: true });
  assert.equal(smp.equalBytes(parsedSend.body, msgBody), true);

  assert.throws(() => smp.parseCommand(4, smp.concatBytes('SEND X ', msgBody)), /notification flag/);
  assert.throws(() => smp.parseCommand(4, smp.concatBytes(newCommand, bytes([1]))), /trailing bytes/);
});

test('broker message codecs handle IDS, MSG, OK, ERR, and NMSG shapes', () => {
  const ids = smp.parseBrokerMessage(4, smp.encodeBrokerMessage(4, {
    type: 'IDS',
    rcvId: filled(24, 7),
    sndId: filled(24, 8),
    rcvPublicDhKey: smp.generateX25519KeyPair(filled(32, 9)).publicKeyDer
  }));
  assert.equal(ids.type, 'IDS');
  assert.equal(ids.rcvId.length, 24);
  assert.equal(ids.sndId.length, 24);

  const msg = smp.parseBrokerMessage(4, smp.encodeBrokerMessage(4, {
    type: 'MSG',
    msgId: filled(24, 10),
    body: bytes([1, 2, 3])
  }));
  assert.equal(msg.type, 'MSG');
  assert.equal(msg.timestamp, 0n);
  assert.equal(smp.equalBytes(msg.body, bytes([1, 2, 3])), true);

  assert.deepEqual(smp.parseBrokerMessage(4, smp.encodeBrokerMessage(4, { type: 'OK' })), { type: 'OK' });
  assert.deepEqual(smp.parseBrokerMessage(4, smp.encodeBrokerMessage(4, { type: 'ERR', error: { type: 'CMD', commandError: 'SYNTAX' } })), {
    type: 'ERR',
    error: { type: 'CMD', commandError: 'SYNTAX' }
  });

  const nmsg = smp.parseBrokerMessage(4, smp.encodeBrokerMessage(4, {
    type: 'NMSG',
    nonce: filled(24, 11),
    meta: bytes([12, 13])
  }));
  assert.equal(nmsg.type, 'NMSG');
  assert.equal(nmsg.nonce.length, 24);
  assert.equal(smp.equalBytes(nmsg.meta, bytes([12, 13])), true);
});

test('signed transmissions verify against the exact signed bytes', () => {
  const signer = smp.generateEd25519KeyPair(filled(32, 12));
  const encoded = smp.encodeSignedTransmission(4, filled(32, 13), {
    privateKey: signer.secretKey,
    corrId: smp.asciiBytes('corr-1'),
    queueId: filled(24, 14),
    command: {
      type: 'SEND',
      flags: { notification: false },
      body: smp.utf8Bytes('hello')
    }
  });

  const parsed = smp.parseSignedTransmission(4, encoded.bytes);
  assert.equal(parsed.command.type, 'SEND');
  assert.equal(smp.equalBytes(parsed.sessionId, filled(32, 13)), true);
  assert.equal(smp.verifyTransmissionSignature(parsed.signed, parsed.signature, signer.publicKey), true);

  const tampered = new Uint8Array(parsed.signed);
  tampered[tampered.length - 1] ^= 1;
  assert.equal(smp.verifyTransmissionSignature(tampered, parsed.signature, signer.publicKey), false);
});

test('SMP v4 transport block batches signed transmissions with strict padding', () => {
  const signer = smp.generateEd25519KeyPair(filled(32, 15));
  const tx1 = smp.encodeSignedTransmission(4, filled(32, 16), {
    privateKey: signer.secretKey,
    corrId: smp.asciiBytes('a'),
    queueId: filled(24, 17),
    command: { type: 'PING' }
  });
  const tx2 = smp.encodeSignedTransmission(4, filled(32, 16), {
    privateKey: signer.secretKey,
    corrId: smp.asciiBytes('b'),
    queueId: filled(24, 18),
    command: { type: 'SUB' }
  });

  const block = smp.encodeTransportBlock(4, [tx1, tx2]);
  assert.equal(block.length, smp.SMP_BLOCK_SIZE);
  const decoded = smp.decodeTransportBlock(4, block);
  assert.equal(decoded.length, 2);
  assert.equal(decoded[0].command.type, 'PING');
  assert.equal(decoded[1].command.type, 'SUB');

  const badPadding = new Uint8Array(block);
  badPadding[badPadding.length - 1] = 0;
  assert.throws(() => smp.decodeTransportBlock(4, badPadding), /non-padding/);

  const emptyBatchBody = smp.padBlock(bytes([0]), smp.SMP_BLOCK_SIZE);
  assert.throws(() => smp.decodeTransportBlock(4, emptyBatchBody), /empty batch/);
});

test('handshake codecs choose the highest mutually supported SMP version', () => {
  const serverBlock = smp.padBlock(smp.encodeServerHandshake({
    minVersion: 1,
    maxVersion: 4,
    sessionId: filled(32, 19)
  }));
  const server = smp.parseServerHandshake(smp.unpadBlock(serverBlock));
  const version = smp.chooseCompatibleVersion(server);
  const client = smp.parseClientHandshake(smp.encodeClientHandshake({
    version,
    keyHash: filled(32, 20)
  }));

  assert.equal(version, 4);
  assert.equal(client.version, 4);
  assert.equal(client.keyHash.length, 32);
  assert.throws(() => smp.chooseCompatibleVersion({ minVersion: 5, maxVersion: 6 }), /incompatible/);
});

test('browser crypto primitives perform protocol-sized authenticated round trips', () => {
  const alice = smp.generateX25519KeyPair(filled(32, 21));
  const bob = smp.generateX25519KeyPair(filled(32, 22));
  const sharedA = smp.x25519SharedSecret(alice.secretKey, bob.publicKey);
  const sharedB = smp.x25519SharedSecret(bob.secretKey, alice.publicKey);
  assert.equal(smp.equalBytes(sharedA, sharedB), true);

  const nonce = filled(24, 23);
  const plaintext = smp.utf8Bytes('browser-native SMP crypto');
  const packet = smp.encryptSecretBox(sharedA, nonce, plaintext, 96);
  assert.equal(smp.equalBytes(smp.decryptSecretBox(sharedB, nonce, packet), plaintext), true);

  const aesKey = filled(32, 24);
  const iv = filled(12, 25);
  const aad = smp.asciiBytes('associated-data');
  const encrypted = smp.encryptAesGcm(aesKey, iv, plaintext, 96, aad);
  assert.equal(smp.equalBytes(smp.decryptAesGcm(aesKey, iv, encrypted.ciphertext, encrypted.tag, aad), plaintext), true);

  const badTag = new Uint8Array(encrypted.tag);
  badTag[0] ^= 1;
  assert.throws(() => smp.decryptAesGcm(aesKey, iv, encrypted.ciphertext, badTag, aad), /decryption failed/);
});

test('public key DER helpers keep SimpleX-compatible algorithm boundaries explicit', () => {
  const sign = smp.generateEd25519KeyPair(filled(32, 26));
  const dh = smp.generateX25519KeyPair(filled(32, 27));
  assert.deepEqual(smp.decodePublicKeyDer(sign.publicKeyDer), {
    algorithm: 'Ed25519',
    rawPublicKey: sign.publicKey
  });
  assert.deepEqual(smp.decodePublicKeyDer(dh.publicKeyDer), {
    algorithm: 'X25519',
    rawPublicKey: dh.publicKey
  });
  assert.throws(() => smp.decodePublicKeyDer(filled(44, 255)), /unsupported public key DER/);
});

test('transport frame fuzzing round-trips bounded byte payloads and rejects oversize payloads', () => {
  fc.assert(fc.property(
    fc.uint8Array({ minLength: 0, maxLength: 512 }),
    fc.uint8Array({ minLength: 0, maxLength: 24 }),
    (body, queueId) => {
      const tx = smp.encodeSignedTransmission(4, filled(32, 28), {
        signature: new Uint8Array(),
        corrId: smp.asciiBytes('fuzz'),
        queueId,
        command: {
          type: 'SEND',
          flags: { notification: body.length % 2 === 0 },
          body
        }
      });
      const block = smp.encodeTransportBlock(4, [tx]);
      const decoded = smp.decodeTransportBlock(4, block)[0];
      assert.equal(decoded.command.type, 'SEND');
      assert.equal(smp.equalBytes(decoded.command.body, body), true);
      assert.equal(smp.equalBytes(decoded.queueId, queueId), true);
    }
  ), { seed: FUZZ_SEED, numRuns: 120 });

  assert.throws(() => smp.padBlock(filled(smp.SMP_BLOCK_SIZE, 1)), /does not fit/);
});

test('browser transport capability is explicit about current browser security blockers', () => {
  const capability = smp.browserTransportCapability();
  assert.equal(capability.rawTcp, false);
  assert.equal(capability.tlsCertificatePinningFromJs, false);
  assert.equal(capability.tlsUniqueChannelBindingFromJs, false);
  assert.equal(capability.requiresBrowserSmpServerProfile, true);
});
