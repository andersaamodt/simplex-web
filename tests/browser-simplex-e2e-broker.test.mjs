import test from 'node:test';
import assert from 'node:assert/strict';

import * as smp from '../src/browser-smp-core.mjs';
import { encryptRcvMessageBody } from '../src/browser-simplex-agent.mjs';
import { createBrowserSimplexClient } from '../src/browser-simplex-client.mjs';
import { createBrowserSimplexContactClient } from '../src/browser-simplex-contact-client.mjs';
import { createBrowserSimplexStore } from '../src/browser-simplex-store.mjs';

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

function idBytes(prefix, value) {
  const out = new Uint8Array(24);
  out.set(smp.asciiBytes(prefix + '-' + value).slice(0, 24));
  return out;
}

class BrokerTransport {
  constructor(broker, name) {
    this.broker = broker;
    this.name = name;
    this.version = 4;
    this.sessionId = broker.sessionId;
    this.inbox = [];
    this.sent = [];
  }

  sendSignedTransmissions(transmissions) {
    for (const transmission of transmissions) {
      this.sent.push(transmission);
      this.broker.process(this, transmission);
    }
  }

  receiveSignedTransmissions() {
    if (!this.inbox.length) throw new Error(this.name + ' broker inbox is empty');
    return Promise.resolve([this.inbox.shift()]);
  }

  enqueue(message) {
    this.inbox.push(message);
  }

  getStatus() {
    return { connected: true, broker: 'browser-profile-test' };
  }
}

class BrowserProfileBroker {
  constructor() {
    this.version = 4;
    this.sessionId = filled(32, 90);
    this.nextQueue = 1;
    this.nextMessage = 1;
    this.queues = new Map();
  }

  connect(name) {
    return new BrokerTransport(this, name);
  }

  enqueueError(transport, parsed, commandError = 'AUTH') {
    transport.enqueue({
      corrId: parsed.corrId,
      queueId: parsed.queueId,
      message: { type: 'ERR', error: { type: 'CMD', commandError } }
    });
  }

  verify(parsed, publicKeyDer) {
    return parsed.signature.length > 0 && smp.ed25519Verify(publicKeyDer, parsed.signed, parsed.signature);
  }

  findByRecipientId(queueId) {
    const key = smp.encodeBase64Url(queueId);
    return this.queues.get(key) || null;
  }

  findBySenderId(queueId) {
    for (const queue of this.queues.values()) {
      if (smp.equalBytes(queue.sndId, queueId)) return queue;
    }
    return null;
  }

  process(transport, transmission) {
    const parsed = smp.parseSignedTransmission(this.version, transmission.bytes || transmission);
    const command = parsed.command;
    if (command.type === 'NEW') return this.newQueue(transport, parsed, command);
    if (command.type === 'SEND') return this.sendMessage(transport, parsed, command);
    const queue = this.findByRecipientId(parsed.queueId);
    if (!queue || !this.verify(parsed, queue.rcvPublicVerifyKey)) return this.enqueueError(transport, parsed);
    if (command.type === 'SUB') return transport.enqueue({ corrId: parsed.corrId, queueId: queue.rcvId, message: { type: 'OK' } });
    if (command.type === 'KEY') {
      queue.senderVerifyKey = command.sndPublicVerifyKey;
      return transport.enqueue({ corrId: parsed.corrId, queueId: queue.rcvId, message: { type: 'OK' } });
    }
    if (command.type === 'ACK') {
      const messageKey = smp.encodeBase64Url(command.msgId);
      const queued = queue.messages.get(messageKey);
      if (queued) queued.acked = true;
      return transport.enqueue({ corrId: parsed.corrId, queueId: queue.rcvId, message: { type: 'OK' } });
    }
    if (command.type === 'DEL') {
      this.queues.delete(smp.encodeBase64Url(queue.rcvId));
      return transport.enqueue({ corrId: parsed.corrId, queueId: queue.rcvId, message: { type: 'OK' } });
    }
    return this.enqueueError(transport, parsed, 'SYNTAX');
  }

  newQueue(transport, parsed, command) {
    if (!this.verify(parsed, command.rcvPublicVerifyKey)) return this.enqueueError(transport, parsed);
    const n = this.nextQueue++;
    const serverDh = smp.generateX25519KeyPair(filled(32, 100 + n));
    const recipientDh = smp.decodePublicKeyDer(command.rcvPublicDhKey);
    const rcvId = idBytes('rcv', n);
    const sndId = idBytes('snd', n);
    const queue = {
      rcvId,
      sndId,
      rcvPublicVerifyKey: command.rcvPublicVerifyKey,
      serverDhSecret: smp.x25519SharedSecret(serverDh.secretKey, recipientDh.rawPublicKey),
      senderVerifyKey: null,
      recipientTransport: transport,
      messages: new Map()
    };
    this.queues.set(smp.encodeBase64Url(rcvId), queue);
    transport.enqueue({
      corrId: parsed.corrId,
      queueId: rcvId,
      message: { type: 'IDS', rcvId, sndId, rcvPublicDhKey: serverDh.publicKeyDer }
    });
  }

  sendMessage(transport, parsed, command) {
    const queue = this.findBySenderId(parsed.queueId);
    if (!queue) return this.enqueueError(transport, parsed, 'NO_QUEUE');
    if (queue.senderVerifyKey && !this.verify(parsed, queue.senderVerifyKey)) return this.enqueueError(transport, parsed);
    const msgId = idBytes('msg', this.nextMessage++);
    const encryptedBody = encryptRcvMessageBody({
      serverDhSecret: queue.serverDhSecret,
      msgId,
      timestamp: BigInt(this.nextMessage),
      flags: command.flags,
      body: command.body
    });
    queue.messages.set(smp.encodeBase64Url(msgId), { msgId, acked: false });
    queue.recipientTransport.enqueue({
      corrId: smp.asciiBytes('msg-' + this.nextMessage),
      queueId: queue.rcvId,
      message: { type: 'MSG', msgId, body: encryptedBody }
    });
    transport.enqueue({ corrId: parsed.corrId, queueId: queue.sndId, message: { type: 'OK' } });
  }
}

function makeClientPair() {
  const broker = new BrowserProfileBroker();
  const aliceTransport = broker.connect('alice');
  const bobTransport = broker.connect('bob');
  const aliceClient = createBrowserSimplexClient({ transport: aliceTransport });
  const bobClient = createBrowserSimplexClient({ transport: bobTransport });
  const aliceStore = createBrowserSimplexStore({ namespace: 'e2e-alice' });
  const bobStore = createBrowserSimplexStore({ namespace: 'e2e-bob' });
  return {
    broker,
    aliceClient,
    bobClient,
    aliceContacts: createBrowserSimplexContactClient({ client: aliceClient, store: aliceStore }),
    bobContacts: createBrowserSimplexContactClient({ client: bobClient, store: bobStore }),
    aliceStore,
    bobStore
  };
}

async function activatePair(pair) {
  await pair.aliceContacts.createInvitation({ id: 'bob', corrId: 'alice-new', rcvSignSeed: filled(32, 1), rcvDhSeed: filled(32, 2) });
  await pair.bobContacts.createInvitation({ id: 'alice', corrId: 'bob-new', rcvSignSeed: filled(32, 3), rcvDhSeed: filled(32, 4) });
  const aliceInbox = pair.aliceStore.loadQueue('bob:inbox');
  const bobInbox = pair.bobStore.loadQueue('alice:inbox');
  const aliceSenderSign = smp.generateEd25519KeyPair(filled(32, 5));
  const bobSenderSign = smp.generateEd25519KeyPair(filled(32, 6));
  await pair.aliceClient.secureQueue(aliceInbox, bobSenderSign.publicKeyDer, { corrId: 'alice-key' });
  await pair.bobClient.secureQueue(bobInbox, aliceSenderSign.publicKeyDer, { corrId: 'bob-key' });

  const aliceDh = smp.generateX25519KeyPair(filled(32, 7));
  const bobDh = smp.generateX25519KeyPair(filled(32, 8));
  const rootKey = filled(32, 9);
  pair.aliceContacts.activateContact('bob', {
    rootKey,
    ownDhKey: aliceDh,
    remoteDhPublicKey: bobDh.publicKey,
    outboundQueue: { sndId: bobInbox.sndId, senderSignKey: aliceSenderSign }
  });
  pair.bobContacts.activateContact('alice', {
    rootKey,
    ownDhKey: bobDh,
    initializeSending: false,
    outboundQueue: { sndId: aliceInbox.sndId, senderSignKey: bobSenderSign }
  });
  return { aliceInbox, bobInbox };
}

test('two browser clients exchange ratcheted messages through a browser-profile SMP broker', async () => {
  const pair = makeClientPair();
  await activatePair(pair);

  await pair.aliceContacts.sendText('bob', 'hello bob', { corrId: 'alice-send-1' });
  const bobReceived = await pair.bobContacts.receiveNext('alice', { ackCorrId: 'bob-ack-1' });
  assert.equal(bobReceived.text, 'hello bob');

  await pair.bobContacts.sendText('alice', 'hello alice', { corrId: 'bob-send-1' });
  const aliceReceived = await pair.aliceContacts.receiveNext('bob', { ackCorrId: 'alice-ack-1' });
  assert.equal(aliceReceived.text, 'hello alice');

  const acked = Array.from(pair.broker.queues.values()).every((queue) => (
    Array.from(queue.messages.values()).every((message) => message.acked)
  ));
  assert.equal(acked, true);
});

test('browser-profile SMP broker rejects forged sender signatures', async () => {
  const pair = makeClientPair();
  const { bobInbox } = await activatePair(pair);
  const wrongSender = smp.generateEd25519KeyPair(filled(32, 66));
  await assert.rejects(
    pair.aliceClient.sendQueueMessage({ sndId: bobInbox.sndId, senderSignKey: wrongSender }, smp.utf8Bytes('forged'), { corrId: 'forged-send' }),
    /CMD AUTH/
  );
});
