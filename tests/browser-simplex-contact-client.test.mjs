import test from 'node:test';
import assert from 'node:assert/strict';

import * as smp from '../src/browser-smp-core.mjs';
import { encryptRcvMessageBody, prepareInitialSenderMessage } from '../src/browser-simplex-agent.mjs';
import { createBrowserSimplexClient } from '../src/browser-simplex-client.mjs';
import { CONTACT_PAYLOAD_PREFIX, createBrowserSimplexContactClient, decodeContactPayload, encodeContactPayload } from '../src/browser-simplex-contact-client.mjs';
import { createBrowserSimplexStore } from '../src/browser-simplex-store.mjs';
import { createRatchetState, encryptRatchetMessage } from '../src/browser-simplex-ratchet.mjs';
import { createBrowserXftpClient } from '../src/browser-xftp-client.mjs';

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

function packetBytes(packet) {
  return smp.utf8Bytes(JSON.stringify({
    h: Array.from(packet.header),
    n: Array.from(packet.nonce),
    c: Array.from(packet.ciphertext),
    t: Array.from(packet.tag)
  }));
}

class FakeTransport {
  constructor() {
    this.version = 4;
    this.sessionId = filled(32, 1);
    this.sent = [];
    this.responses = [];
  }

  sendSignedTransmissions(transmissions) {
    this.sent.push(...transmissions);
  }

  receiveSignedTransmissions() {
    if (!this.responses.length) throw new Error('no fake responses queued');
    return Promise.resolve([this.responses.shift()]);
  }

  pushResponse(corrId, message, queueId = new Uint8Array()) {
    this.responses.push({
      corrId: typeof corrId === 'string' ? smp.asciiBytes(corrId) : corrId,
      queueId,
      message
    });
  }
}

function xftpProfile() {
  return {
    version: 1,
    transport: 'websocket',
    url: 'wss://xftp.example.test/upload',
    allowedOrigins: ['https://app.example.test'],
    keyHash: smp.encodeBase64Url(filled(32, 40)),
    xftpAddress: 'xftp://fingerprint@xftp.example.test'
  };
}

function createMemoryXftpServer() {
  const chunks = new Map();
  const puts = [];
  return {
    puts,
    async putChunk(packet) {
      puts.push(packet);
      chunks.set(packet.fileId + ':' + packet.index, {
        index: packet.index,
        size: packet.size,
        sha256: packet.sha256,
        ciphertext: new Uint8Array(packet.ciphertext),
        tag: new Uint8Array(packet.tag),
        ciphertextSha256: packet.ciphertextSha256
      });
    },
    async getChunk(fileId, index) {
      const chunk = chunks.get(fileId + ':' + index);
      if (!chunk) throw new Error('missing chunk');
      return {
        ...chunk,
        ciphertext: new Uint8Array(chunk.ciphertext),
        tag: new Uint8Array(chunk.tag)
      };
    }
  };
}

test('contact client creates invitation activates contact and sends ratcheted text', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const serverDh = smp.generateX25519KeyPair(filled(32, 2));
  transport.pushResponse('new-1', {
    type: 'IDS',
    rcvId: filled(24, 3),
    sndId: filled(24, 4),
    rcvPublicDhKey: serverDh.publicKeyDer
  });

  const invited = await contacts.createInvitation({
    id: 'alice',
    corrId: 'new-1',
    server: { scheme: 'smp', keyHash: filled(32, 72), host: 'smp.example.test', port: '5223' },
    rcvSignSeed: filled(32, 5),
    rcvDhSeed: filled(32, 6)
  });
  assert.equal(invited.state, 'invited');
  assert.equal(invited.invitationUri.startsWith('smp://'), true);
  assert.equal(contacts.invitationUri('alice'), invited.invitationUri);

  const remoteDh = smp.generateX25519KeyPair(filled(32, 7));
  const outbox = {
    sndId: filled(24, 8),
    senderSignKey: smp.generateEd25519KeyPair(filled(32, 9))
  };
  contacts.activateContact('alice', {
    rootKey: filled(32, 10),
    ownDhSeed: filled(32, 11),
    remoteDhPublicKey: remoteDh.publicKey,
    outboundQueue: outbox
  });
  transport.pushResponse('send-1', { type: 'OK' }, outbox.sndId);
  await contacts.sendText('alice', 'hello', { corrId: 'send-1' });

  const sent = smp.parseSignedTransmission(4, transport.sent[1].bytes);
  assert.equal(sent.command.type, 'SEND');
  assert.equal(smp.equalBytes(sent.queueId, outbox.sndId), true);
  assert.notEqual(smp.utf8Text(sent.command.body).includes('hello'), true);
});

test('contact client requests contact from invitation with encrypted initial confirmation', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-request' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 57));
  const invitationUri = smp.formatSmpQueueUri({
    server: { scheme: 'smp', keyHash: filled(32, 58), host: 'smp.example.test', port: '5223' },
    queueId: filled(24, 59),
    recipientDhPublicKey: recipientDh.publicKeyDer
  });

  transport.pushResponse('req-1', { type: 'OK' }, filled(24, 59));
  const contact = await contacts.requestContact('bob', invitationUri, {
    corrId: 'req-1',
    ownDhSeed: filled(32, 60),
    senderSignSeed: filled(32, 61),
    nonce: filled(24, 62),
    profile: { displayName: 'Alice' }
  });

  assert.equal(contact.state, 'requested');
  assert.equal(store.loadContact('bob').state, 'requested');
  assert.equal(store.loadQueue('bob:outbox').sndId.length, 24);
  assert.ok(store.loadRatchet('bob').rootKey instanceof Uint8Array);
  const sent = smp.parseSignedTransmission(4, transport.sent[0].bytes);
  assert.equal(sent.command.type, 'SEND');
  assert.equal(sent.signature.length, 0);
  assert.equal(Buffer.from(sent.command.body).includes(Buffer.from('Alice')), false);
});

test('contact client receives contact request secures queue and stores receiving ratchet', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-accept' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 63));
  const senderDh = smp.generateX25519KeyPair(filled(32, 64));
  const shared = smp.x25519SharedSecret(senderDh.secretKey, recipientDh.publicKey);
  const queue = {
    rcvId: filled(24, 65),
    sndId: filled(24, 66),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 67)),
    rcvDhKey: recipientDh,
    serverDhSecret: filled(32, 68)
  };
  store.saveContact('alice', { id: 'alice', state: 'invited', inboxQueueId: 'alice:inbox' });
  store.saveQueue('alice:inbox', queue);

  const prepared = prepareInitialSenderMessage({
    version: 4,
    sessionId: transport.sessionId,
    corrId: smp.asciiBytes('initial'),
    senderQueueId: queue.sndId,
    senderSignSeed: filled(32, 69),
    e2eSharedSecret: shared,
    senderE2ePubDhKey: senderDh.publicKeyDer,
    nonce: filled(24, 70),
    body: smp.utf8Bytes(JSON.stringify({ type: 'contact-request', profile: { displayName: 'Bob' } }))
  });
  const msgId = filled(24, 71);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 789n,
    body: prepared.envelope
  });
  transport.pushResponse('msg-request', { type: 'MSG', msgId, body }, queue.rcvId);
  transport.pushResponse('key-1', { type: 'OK' }, queue.rcvId);
  transport.pushResponse('ack-2', { type: 'OK' }, queue.rcvId);

  const accepted = await contacts.receiveContactRequest('alice', {
    keyCorrId: 'key-1',
    ackCorrId: 'ack-2'
  });
  assert.equal(accepted.contact.state, 'active');
  assert.equal(accepted.request.profile.displayName, 'Bob');
  assert.equal(accepted.timestamp, 789n);
  assert.equal(store.loadContact('alice').remoteProfile.displayName, 'Bob');
  assert.ok(store.loadRatchet('alice').rootKey instanceof Uint8Array);
  const keyCommand = smp.parseSignedTransmission(4, transport.sent[0].bytes).command;
  const ackCommand = smp.parseSignedTransmission(4, transport.sent[1].bytes).command;
  assert.equal(keyCommand.type, 'KEY');
  assert.equal(ackCommand.type, 'ACK');
  assert.equal(smp.equalBytes(ackCommand.msgId, msgId), true);
});

test('contact client schedules failed sends for retry', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-fail' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  contacts.store.saveContact('alice', { id: 'alice', state: 'active', outboundQueue: { sndId: filled(24, 12) } });
  contacts.store.saveRatchet('alice', {
    rootKey: filled(32, 13),
    ownDhKey: smp.generateX25519KeyPair(filled(32, 14)),
    remoteDhPublicKey: smp.generateX25519KeyPair(filled(32, 15)).publicKey,
    sendingChainKey: filled(32, 16)
  });

  await assert.rejects(() => contacts.sendText('alice', 'retry me', { corrId: 'send-2', clientMessageId: 'm1' }), /no fake responses/);
  assert.equal(store.listPending().length, 1);
  assert.equal(store.listPending()[0].payload.contactId, 'alice');
});

test('contact client receives decrypts and acknowledges queue messages', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-receive' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const aliceDh = smp.generateX25519KeyPair(filled(32, 20));
  const bobDh = smp.generateX25519KeyPair(filled(32, 21));
  const root = filled(32, 22);
  const senderRatchet = createRatchetState({ rootKey: root, ownDhKey: aliceDh, remoteDhPublicKey: bobDh.publicKey });
  const receiverRatchet = createRatchetState({ rootKey: root, ownDhKey: bobDh, initializeSending: false });
  const queue = {
    rcvId: filled(24, 23),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 24)),
    serverDhSecret: filled(32, 25)
  };
  store.saveContact('alice', { id: 'alice', state: 'active' });
  store.saveQueue('alice:inbox', queue);
  store.saveRatchet('alice', receiverRatchet);

  const packet = encryptRatchetMessage(senderRatchet, smp.utf8Bytes('hello from queue'), { nonce: filled(24, 26) }).packet;
  const msgId = filled(24, 27);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 123n,
    body: packetBytes(packet)
  });
  transport.pushResponse('msg-1', { type: 'MSG', msgId, body }, queue.rcvId);
  transport.pushResponse('ack-1', { type: 'OK' }, queue.rcvId);

  const received = await contacts.receiveNext('alice', { ackCorrId: 'ack-1' });
  assert.equal(received.text, 'hello from queue');
  assert.equal(received.timestamp, 123n);
  const ack = smp.parseSignedTransmission(4, transport.sent[0].bytes);
  assert.equal(ack.command.type, 'ACK');
  assert.equal(smp.equalBytes(ack.command.msgId, msgId), true);
});

test('contact client uploads files through XFTP and sends only a ratcheted file descriptor', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-file-send' });
  const xftpServer = createMemoryXftpServer();
  const xftpClient = createBrowserXftpClient({ server: xftpServer, profile: xftpProfile() });
  const contacts = createBrowserSimplexContactClient({ client, store, xftpClient });
  const outbox = {
    sndId: filled(24, 41),
    senderSignKey: smp.generateEd25519KeyPair(filled(32, 42))
  };
  store.saveContact('alice', { id: 'alice', state: 'active', outboundQueue: outbox });
  store.saveRatchet('alice', {
    rootKey: filled(32, 43),
    ownDhKey: smp.generateX25519KeyPair(filled(32, 44)),
    remoteDhPublicKey: smp.generateX25519KeyPair(filled(32, 45)).publicKey,
    sendingChainKey: filled(32, 46)
  });

  transport.pushResponse('file-send', { type: 'OK' }, outbox.sndId);
  const fileBytes = smp.utf8Bytes('file secret '.repeat(80));
  const result = await contacts.sendFile('alice', fileBytes, {
    corrId: 'file-send',
    name: '../notes.txt',
    mime: 'text/plain',
    fileId: 'contact-file-1',
    chunkSize: 1024,
    fileRootKey: filled(32, 47)
  });

  assert.equal(result.file.manifest.name, '.._notes.txt');
  assert.equal(xftpServer.puts.length, result.file.manifest.chunkCount);
  assert.equal(xftpServer.puts.some((packet) => Buffer.from(packet.ciphertext).includes(Buffer.from('file secret'))), false);
  const sent = smp.parseSignedTransmission(4, transport.sent[0].bytes);
  assert.equal(sent.command.type, 'SEND');
  assert.equal(Buffer.from(sent.command.body).includes(Buffer.from('file secret')), false);
  assert.equal(Buffer.from(sent.command.body).includes(Buffer.from(result.file.rootKey)), false);
});

test('contact client receives XFTP file descriptors and downloads verified file bytes', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-file-receive' });
  const xftpServer = createMemoryXftpServer();
  const xftpClient = createBrowserXftpClient({ server: xftpServer, profile: xftpProfile() });
  const contacts = createBrowserSimplexContactClient({ client, store, xftpClient });
  const aliceDh = smp.generateX25519KeyPair(filled(32, 48));
  const bobDh = smp.generateX25519KeyPair(filled(32, 49));
  const root = filled(32, 50);
  const senderRatchet = createRatchetState({ rootKey: root, ownDhKey: aliceDh, remoteDhPublicKey: bobDh.publicKey });
  const receiverRatchet = createRatchetState({ rootKey: root, ownDhKey: bobDh, initializeSending: false });
  const queue = {
    rcvId: filled(24, 51),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 52)),
    serverDhSecret: filled(32, 53)
  };
  store.saveContact('alice', { id: 'alice', state: 'active' });
  store.saveQueue('alice:inbox', queue);
  store.saveRatchet('alice', receiverRatchet);

  const fileBytes = smp.utf8Bytes('download me '.repeat(90));
  const upload = await xftpClient.uploadFile(fileBytes, {
    name: 'remote.txt',
    mime: 'text/plain',
    fileId: 'contact-file-2',
    rootKey: filled(32, 54),
    chunkSize: 1024
  });
  const payloadText = encodeContactPayload({
    type: 'file',
    file: {
      manifest: upload.manifest,
      rootKey: smp.encodeBase64Url(upload.rootKey),
      uploadedChunks: upload.uploadedChunks
    }
  });
  const packet = encryptRatchetMessage(senderRatchet, smp.utf8Bytes(payloadText), { nonce: filled(24, 55) }).packet;
  const msgId = filled(24, 56);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 456n,
    body: packetBytes(packet)
  });
  transport.pushResponse('file-msg', { type: 'MSG', msgId, body }, queue.rcvId);
  transport.pushResponse('file-ack', { type: 'OK' }, queue.rcvId);

  const received = await contacts.receiveNext('alice', { ackCorrId: 'file-ack' });
  assert.equal(received.text, '');
  assert.equal(received.payload.type, 'file');
  assert.equal(received.file.manifest.name, 'remote.txt');
  assert.equal(smp.equalBytes(await contacts.downloadReceivedFile(received), fileBytes), true);
});

test('contact client drains due retry tasks through the queue client', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-retry-drain' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const outbox = {
    sndId: filled(24, 28),
    senderSignKey: smp.generateEd25519KeyPair(filled(32, 29))
  };
  store.saveContact('alice', { id: 'alice', state: 'active', outboundQueue: outbox });
  store.saveRatchet('alice', {
    rootKey: filled(32, 30),
    ownDhKey: smp.generateX25519KeyPair(filled(32, 31)),
    remoteDhPublicKey: smp.generateX25519KeyPair(filled(32, 32)).publicKey,
    sendingChainKey: filled(32, 33)
  });

  await assert.rejects(() => contacts.sendText('alice', 'retry drain', { corrId: 'send-miss', clientMessageId: 'm2' }), /no fake responses/);
  transport.pushResponse('retry-ok', { type: 'OK' }, outbox.sndId);
  const result = await contacts.drainDueRetries({ now: Date.now() + 60000, sendOptions: { corrId: 'retry-ok' } });
  assert.equal(result.length, 1);
  assert.equal(result[0].ok, true);
  assert.equal(store.listPending()[0].completedAt > 0, true);
});

test('contact payload decoder preserves plain text and rejects malformed prefixed payloads', () => {
  assert.deepEqual(decodeContactPayload('hello'), { type: 'text', text: 'hello' });
  assert.throws(() => decodeContactPayload(CONTACT_PAYLOAD_PREFIX + '{"type":"file"}'), /file payload/i);
  assert.throws(() => decodeContactPayload(CONTACT_PAYLOAD_PREFIX + '<script>bad()</script>'), /JSON/i);
});
