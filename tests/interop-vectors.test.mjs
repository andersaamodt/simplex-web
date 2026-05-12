import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import * as smp from '../src/browser-smp-core.mjs';
import * as agent from '../src/browser-simplex-agent.mjs';
import { assembleXftpDownload, createXftpUpload } from '../src/browser-xftp-core.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorPath = join(__dirname, 'vectors', 'simplex-web-interop-v1.json');

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

function hex(bytes) {
  return smp.bytesToHex(bytes);
}

function bytes(hexValue) {
  return smp.hexToBytes(hexValue);
}

async function loadVectors() {
  return JSON.parse(await readFile(vectorPath, 'utf8'));
}

test('SMP local interoperability vectors are stable and parseable', async () => {
  const vectors = await loadVectors();
  const rcvSign = smp.generateEd25519KeyPair(filled(32, 3));
  const rcvDh = smp.generateX25519KeyPair(filled(32, 4));
  const sndSign = smp.generateEd25519KeyPair(filled(32, 5));
  const recipientDh = smp.generateX25519KeyPair(filled(32, 7));
  const session = filled(32, 1);
  const queue = filled(24, 2);

  assert.equal(hex(smp.encodeCommand(4, {
    type: 'NEW',
    rcvPublicVerifyKey: rcvSign.publicKeyDer,
    rcvPublicDhKey: rcvDh.publicKeyDer
  })), vectors.smp.newCommand);
  assert.equal(hex(smp.encodeCommand(4, {
    type: 'KEY',
    sndPublicVerifyKey: sndSign.publicKeyDer
  })), vectors.smp.keyCommand);
  assert.equal(hex(smp.encodeCommand(4, {
    type: 'SEND',
    flags: { notification: true },
    body: smp.utf8Bytes('vector message')
  })), vectors.smp.sendCommand);

  assert.equal(hex(smp.encodeBrokerMessage(4, {
    type: 'IDS',
    rcvId: filled(24, 8),
    sndId: filled(24, 9),
    rcvPublicDhKey: rcvDh.publicKeyDer
  })), vectors.smp.idsBroker);
  assert.equal(hex(smp.encodeBrokerMessage(4, {
    type: 'MSG',
    msgId: filled(24, 10),
    body: smp.utf8Bytes('server body')
  })), vectors.smp.msgBroker);
  assert.equal(hex(smp.encodeBrokerMessage(4, {
    type: 'ERR',
    error: { type: 'CMD', commandError: 'SYNTAX' }
  })), vectors.smp.errBroker);
  assert.equal(hex(smp.encodeServerHandshake({ minVersion: 3, maxVersion: 4, sessionId: session })), vectors.smp.serverHandshake);
  assert.equal(hex(smp.encodeClientHandshake({ version: 4, keyHash: filled(32, 11) })), vectors.smp.clientHandshake);

  const signed = smp.encodeSignedTransmission(4, session, {
    privateKey: sndSign.secretKey,
    corrId: smp.asciiBytes('vec-1'),
    queueId: queue,
    command: { type: 'SEND', flags: { notification: false }, body: smp.utf8Bytes('signed vector') }
  });
  assert.equal(hex(signed.bytes), vectors.smp.signedTransmission.bytes);
  assert.equal(hex(signed.signed), vectors.smp.signedTransmission.signed);
  assert.equal(hex(signed.signature), vectors.smp.signedTransmission.signature);
  assert.equal(smp.verifyTransmissionSignature(bytes(vectors.smp.signedTransmission.signed), bytes(vectors.smp.signedTransmission.signature), bytes(vectors.smp.signedTransmission.publicKey)), true);
  assert.equal(hex(smp.encodeTransportBlock(4, [signed]).slice(0, 96)), vectors.smp.transportBlockPrefix);
  assert.equal(smp.formatSmpQueueUri({
    server: { scheme: 'smp', keyHash: filled(32, 12), host: 'smp.example.test', port: '5223' },
    queueId: queue,
    recipientDhPublicKey: recipientDh.publicKeyDer
  }), vectors.smp.queueUri);

  assert.equal(smp.parseCommand(4, bytes(vectors.smp.sendCommand)).type, 'SEND');
  assert.equal(smp.parseBrokerMessage(4, bytes(vectors.smp.errBroker)).error.commandError, 'SYNTAX');
  assert.equal(smp.parseSignedTransmission(4, bytes(vectors.smp.signedTransmission.bytes)).command.type, 'SEND');
});

test('agent and XFTP local interoperability vectors are stable and parseable', async () => {
  const vectors = await loadVectors();
  const senderDh = smp.generateX25519KeyPair(filled(32, 6));
  const recipientDh = smp.generateX25519KeyPair(filled(32, 7));
  const sndSign = smp.generateEd25519KeyPair(filled(32, 5));
  const shared = smp.x25519SharedSecret(senderDh.secretKey, recipientDh.publicKey);
  const envelope = agent.encryptClientMessage({
    sharedSecret: shared,
    nonce: filled(24, 13),
    publicHeader: { version: 1, e2ePubDhKey: senderDh.publicKeyDer },
    privateHeader: { type: 'confirmation', senderPublicVerifyKey: sndSign.publicKeyDer },
    body: smp.utf8Bytes('agent vector'),
    paddedLength: 160
  });
  assert.equal(hex(envelope), vectors.agent.clientEnvelope);
  const decrypted = agent.decryptClientMessageEnvelope({
    sharedSecret: smp.x25519SharedSecret(recipientDh.secretKey, senderDh.publicKey),
    envelope: bytes(vectors.agent.clientEnvelope)
  });
  assert.equal(decrypted.privateHeader.type, 'confirmation');
  assert.equal(smp.utf8Text(decrypted.body), 'agent vector');

  const upload = createXftpUpload(smp.utf8Bytes('xftp vector payload'), {
    rootKey: filled(32, 14),
    fileId: 'vector-file',
    name: '../vector.txt',
    mime: 'text/plain',
    chunkSize: 1024
  });
  assert.deepEqual(upload.manifest, vectors.xftp.manifest);
  assert.equal(hex(upload.rootKey), vectors.xftp.rootKey);
  assert.equal(hex(upload.chunks[0].ciphertext), vectors.xftp.chunk0.ciphertext);
  assert.equal(hex(upload.chunks[0].tag), vectors.xftp.chunk0.tag);
  assert.equal(smp.utf8Text(assembleXftpDownload(vectors.xftp.manifest, [{
    ...vectors.xftp.chunk0,
    ciphertext: bytes(vectors.xftp.chunk0.ciphertext),
    tag: bytes(vectors.xftp.chunk0.tag)
  }], bytes(vectors.xftp.rootKey))), 'xftp vector payload');
});
