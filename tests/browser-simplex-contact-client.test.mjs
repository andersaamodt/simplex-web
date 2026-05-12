import test from 'node:test';
import assert from 'node:assert/strict';

import * as smp from '../src/browser-smp-core.mjs';
import { createBrowserSimplexClient } from '../src/browser-simplex-client.mjs';
import { createBrowserSimplexContactClient } from '../src/browser-simplex-contact-client.mjs';
import { createBrowserSimplexStore } from '../src/browser-simplex-store.mjs';

function filled(length, value) {
  return new Uint8Array(length).fill(value);
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
