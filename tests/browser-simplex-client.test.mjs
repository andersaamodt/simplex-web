import test from 'node:test';
import assert from 'node:assert/strict';

import * as smp from '../src/browser-smp-core.mjs';
import { createBrowserSimplexClient } from '../src/browser-simplex-client.mjs';

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

  getStatus() {
    return { connected: true };
  }
}

function inspectSent(transport, index = 0) {
  return smp.parseSignedTransmission(4, transport.sent[index].bytes || transport.sent[index]);
}

test('client creates a queue through signed NEW and IDS completion', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const serverDh = smp.generateX25519KeyPair(filled(32, 2));
  transport.pushResponse('new-1', {
    type: 'IDS',
    rcvId: filled(24, 3),
    sndId: filled(24, 4),
    rcvPublicDhKey: serverDh.publicKeyDer
  });

  const queue = await client.createQueue({
    corrId: 'new-1',
    label: 'alice-inbox',
    rcvSignSeed: filled(32, 5),
    rcvDhSeed: filled(32, 6)
  });

  const sent = inspectSent(transport);
  assert.equal(sent.command.type, 'NEW');
  assert.equal(sent.queueId.length, 0);
  assert.equal(smp.equalBytes(queue.rcvId, filled(24, 3)), true);
  assert.equal(smp.equalBytes(queue.sndId, filled(24, 4)), true);
  assert.equal(client.status().queueCount, 1);
  assert.equal(client.status().queues[0].label, 'alice-inbox');
});

test('client signs queue-scoped subscribe ack secure and delete commands', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const serverDh = smp.generateX25519KeyPair(filled(32, 7));
  transport.pushResponse('new-2', {
    type: 'IDS',
    rcvId: filled(24, 8),
    sndId: filled(24, 9),
    rcvPublicDhKey: serverDh.publicKeyDer
  });
  const queue = await client.createQueue({
    corrId: 'new-2',
    label: 'queue',
    rcvSignSeed: filled(32, 10),
    rcvDhSeed: filled(32, 11)
  });

  transport.pushResponse('sub-1', { type: 'OK' }, queue.rcvId);
  await client.subscribeQueue('queue', { corrId: 'sub-1' });
  transport.pushResponse('ack-1', { type: 'OK' }, queue.rcvId);
  await client.acknowledgeMessage(queue, filled(24, 12), { corrId: 'ack-1' });
  transport.pushResponse('key-1', { type: 'OK' }, queue.rcvId);
  await client.secureQueue(queue, smp.generateEd25519KeyPair(filled(32, 13)).publicKeyDer, { corrId: 'key-1' });
  transport.pushResponse('del-1', { type: 'OK' }, queue.rcvId);
  await client.deleteQueue(queue, { corrId: 'del-1' });

  const commands = transport.sent.slice(1).map((sent) => smp.parseSignedTransmission(4, sent.bytes || sent).command.type);
  assert.deepEqual(commands, ['SUB', 'ACK', 'KEY', 'DEL']);
  for (const sent of transport.sent.slice(1)) {
    const parsed = smp.parseSignedTransmission(4, sent.bytes || sent);
    assert.equal(smp.equalBytes(parsed.queueId, queue.rcvId), true);
    assert.equal(smp.ed25519Verify(queue.rcvSignKey.publicKey, parsed.signed, parsed.signature), true);
  }
});

test('client sends initial confirmation as unsigned SEND and requires OK', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const recipientE2e = smp.generateX25519KeyPair(filled(32, 14));
  const senderE2e = smp.generateX25519KeyPair(filled(32, 15));
  const shared = smp.x25519SharedSecret(senderE2e.secretKey, recipientE2e.publicKey);
  transport.pushResponse('confirm-1', { type: 'OK' }, filled(24, 16));

  const result = await client.sendInitialConfirmation({
    corrId: 'confirm-1',
    senderQueueId: filled(24, 16),
    senderSignSeed: filled(32, 17),
    e2eSharedSecret: shared,
    senderE2ePubDhKey: senderE2e.publicKeyDer,
    nonce: filled(24, 18),
    body: smp.utf8Bytes('profile')
  });

  const sent = inspectSent(transport);
  assert.equal(sent.command.type, 'SEND');
  assert.equal(sent.signature.length, 0);
  assert.equal(smp.equalBytes(result.senderSignKey.publicKeyDer, smp.generateEd25519KeyPair(filled(32, 17)).publicKeyDer), true);
});

test('client fails closed on broker errors and unmatched correlation ids', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  transport.pushResponse('new-err', { type: 'ERR', error: { type: 'CMD', commandError: 'AUTH' } });
  await assert.rejects(
    client.createQueue({ corrId: 'new-err', rcvSignSeed: filled(32, 19), rcvDhSeed: filled(32, 20) }),
    /CMD AUTH/
  );

  const transport2 = new FakeTransport();
  const client2 = createBrowserSimplexClient({ transport: transport2 });
  transport2.pushResponse('wrong-id', { type: 'OK' });
  await assert.rejects(
    client2.createQueue({
      corrId: 'new-timeout',
      rcvSignSeed: filled(32, 21),
      rcvDhSeed: filled(32, 22),
      maxBatches: 1
    }),
    /no SMP response matched/
  );
});

test('client buffers unmatched broker messages while waiting for a correlation id', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const queue = {
    rcvId: filled(24, 34),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 35))
  };
  const msgId = filled(24, 36);
  transport.responses.push(
    { corrId: smp.asciiBytes('async-msg'), queueId: queue.rcvId, message: { type: 'MSG', msgId, body: filled(32, 37) } },
    { corrId: smp.asciiBytes('sub-async'), queueId: queue.rcvId, message: { type: 'OK' } }
  );

  await client.subscribeQueue(queue, { corrId: 'sub-async', maxBatches: 2 });
  assert.equal(client.status().pendingTransmissionCount, 1);
  const received = await client.receiveQueueMessage(queue, { maxBatches: 1 });
  assert.equal(smp.equalBytes(received.message.msgId, msgId), true);
  assert.equal(client.status().pendingTransmissionCount, 0);
});

test('client buffers unmatched OK responses while receiving queue messages', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const queue = {
    rcvId: filled(24, 38),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 39))
  };
  const msgId = filled(24, 40);
  transport.responses.push(
    { corrId: smp.asciiBytes('send-ok'), queueId: queue.rcvId, message: { type: 'OK' } },
    { corrId: smp.asciiBytes('msg-async'), queueId: queue.rcvId, message: { type: 'MSG', msgId, body: filled(32, 41) } }
  );

  const received = await client.receiveQueueMessage(queue, { maxBatches: 2 });
  assert.equal(smp.equalBytes(received.message.msgId, msgId), true);
  const ok = await client.receiveForCorr(smp.asciiBytes('send-ok'), { maxBatches: 1 });
  assert.equal(ok.message.type, 'OK');
});

test('client caps pending broker buffer under unsolicited traffic', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport, maxPendingTransmissions: 16 });
  for (let i = 0; i < 40; i += 1) {
    transport.responses.push({
      corrId: smp.asciiBytes('noise-' + i),
      queueId: filled(24, 42),
      message: { type: 'OK' }
    });
  }
  transport.responses.push({
    corrId: smp.asciiBytes('wanted'),
    queueId: filled(24, 42),
    message: { type: 'OK' }
  });
  await client.receiveForCorr('wanted', { maxBatches: 41 });
  assert.equal(client.status().pendingTransmissionCount, 16);
});

test('client rejects hostile correlation ids before transport side effects', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  await assert.rejects(
    client.createQueue({
      corrId: 'bad\nid',
      rcvSignSeed: filled(32, 23),
      rcvDhSeed: filled(32, 24)
    }),
    /correlation id/
  );
  assert.equal(transport.sent.length, 0);
});
