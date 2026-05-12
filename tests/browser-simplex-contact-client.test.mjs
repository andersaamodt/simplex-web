import test from 'node:test';
import assert from 'node:assert/strict';

import * as smp from '../src/browser-smp-core.mjs';
import { encryptRcvMessageBody } from '../src/browser-simplex-agent.mjs';
import { createBrowserSimplexClient } from '../src/browser-simplex-client.mjs';
import { createBrowserSimplexContactClient } from '../src/browser-simplex-contact-client.mjs';
import { createBrowserSimplexStore } from '../src/browser-simplex-store.mjs';
import { createRatchetState, encryptRatchetMessage } from '../src/browser-simplex-ratchet.mjs';

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
    rcvSignSeed: filled(32, 5),
    rcvDhSeed: filled(32, 6)
  });
  assert.equal(invited.state, 'invited');

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
