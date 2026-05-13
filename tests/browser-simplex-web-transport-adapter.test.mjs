import test from 'node:test';
import assert from 'node:assert/strict';

import * as smp from '../src/browser-smp-core.mjs';
import { encryptRcvMessageBody } from '../src/browser-simplex-agent.mjs';
import { createBrowserSimplexStore } from '../src/browser-simplex-store.mjs';
import { createSimplexWebTransportAdapter, registerSimplexWebTransportAdapter } from '../src/browser-simplex-web-transport-adapter.mjs';

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

function idBytes(prefix, value) {
  var out = new Uint8Array(24);
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
  }

  sendSignedTransmissions(transmissions) {
    for (var transmission of transmissions) this.broker.process(this, transmission);
  }

  receiveSignedTransmissions() {
    if (!this.inbox.length) {
      var error = new Error(this.name + ' broker inbox is empty');
      error.code = 'SIMPLEX_CLIENT_TIMEOUT';
      return Promise.reject(error);
    }
    return Promise.resolve([this.inbox.shift()]);
  }

  enqueue(message) {
    this.inbox.push(message);
  }

  getStatus() {
    return { connected: true, broker: 'browser-profile-test' };
  }

  close() {}
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
    return this.queues.get(smp.encodeBase64Url(queueId)) || null;
  }

  findBySenderId(queueId) {
    for (var queue of this.queues.values()) {
      if (smp.equalBytes(queue.sndId, queueId)) return queue;
    }
    return null;
  }

  process(transport, transmission) {
    var parsed = smp.parseSignedTransmission(this.version, transmission.bytes || transmission);
    var command = parsed.command;
    if (command.type === 'NEW') return this.newQueue(transport, parsed, command);
    if (command.type === 'SEND') return this.sendMessage(transport, parsed, command);
    var queue = this.findByRecipientId(parsed.queueId);
    if (!queue || !this.verify(parsed, queue.rcvPublicVerifyKey)) return this.enqueueError(transport, parsed);
    if (command.type === 'DEL') {
      this.queues.delete(smp.encodeBase64Url(queue.rcvId));
      return transport.enqueue({ corrId: parsed.corrId, queueId: queue.rcvId, message: { type: 'OK' } });
    }
    if (command.type === 'KEY') {
      queue.senderVerifyKey = command.sndPublicVerifyKey;
      return transport.enqueue({ corrId: parsed.corrId, queueId: queue.rcvId, message: { type: 'OK' } });
    }
    if (command.type === 'ACK') {
      var queued = queue.messages.get(smp.encodeBase64Url(command.msgId));
      if (queued) queued.acked = true;
      return transport.enqueue({ corrId: parsed.corrId, queueId: queue.rcvId, message: { type: 'OK' } });
    }
    return this.enqueueError(transport, parsed, 'SYNTAX');
  }

  newQueue(transport, parsed, command) {
    if (!this.verify(parsed, command.rcvPublicVerifyKey)) return this.enqueueError(transport, parsed);
    var n = this.nextQueue++;
    var serverDh = smp.generateX25519KeyPair(filled(32, 100 + n));
    var recipientDh = smp.decodePublicKeyDer(command.rcvPublicDhKey);
    var rcvId = idBytes('rcv', n);
    var sndId = idBytes('snd', n);
    var queue = {
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
    var queue = this.findBySenderId(parsed.queueId);
    if (!queue) return this.enqueueError(transport, parsed, 'NO_QUEUE');
    if (queue.senderVerifyKey && !this.verify(parsed, queue.senderVerifyKey)) return this.enqueueError(transport, parsed);
    var msgId = idBytes('msg', this.nextMessage++);
    var encryptedBody = encryptRcvMessageBody({
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

async function activateAdapterPair(alice, bob, aliceStore, bobStore) {
  await alice.createInvitation({ contact_id: 'bob', corrId: 'alice-new', rcvSignSeed: filled(32, 1), rcvDhSeed: filled(32, 2) });
  await bob.createInvitation({ contact_id: 'alice', corrId: 'bob-new', rcvSignSeed: filled(32, 3), rcvDhSeed: filled(32, 4) });
  var aliceInbox = aliceStore.loadQueue('bob:inbox');
  var bobInbox = bobStore.loadQueue('alice:inbox');
  var aliceSenderSign = smp.generateEd25519KeyPair(filled(32, 5));
  var bobSenderSign = smp.generateEd25519KeyPair(filled(32, 6));
  await alice.simplexClient.secureQueue(aliceInbox, bobSenderSign.publicKeyDer, { corrId: 'alice-key' });
  await bob.simplexClient.secureQueue(bobInbox, aliceSenderSign.publicKeyDer, { corrId: 'bob-key' });

  var aliceDh = smp.generateX25519KeyPair(filled(32, 7));
  var bobDh = smp.generateX25519KeyPair(filled(32, 8));
  var rootKey = filled(32, 9);
  alice.activateContact({
    contact_id: 'bob',
    rootKey,
    ownDhKey: aliceDh,
    remoteDhPublicKey: bobDh.publicKey,
    outboundQueue: { sndId: bobInbox.sndId, senderSignKey: aliceSenderSign }
  });
  bob.activateContact({
    contact_id: 'alice',
    rootKey,
    ownDhKey: bobDh,
    initializeSending: false,
    outboundQueue: { sndId: aliceInbox.sndId, senderSignKey: bobSenderSign }
  });
}

test('SimplexWebTransport adapter normalizes facade sends files receives and registration', async () => {
  var sentText = [];
  var sentFiles = [];
  var acceptCalls = [];
  var deleteCalls = [];
  var localDeleteCalls = [];
  var received = [{
    duplicate: true,
    payload: { type: 'duplicate' },
    msgId: smp.asciiBytes('msg-dup')
  }, {
    text: 'reply',
    msgId: smp.asciiBytes('msg-1'),
    timestamp: 123n
  }];
  var timeout = new Error('empty');
  timeout.code = 'SIMPLEX_CLIENT_TIMEOUT';
  var contactClient = {
    listContacts() {
      return [{ id: 'alice', state: 'active' }];
    },
    sendText(id, text, options) {
      sentText.push({ id, text, options });
      return Promise.resolve({ message: { type: 'OK' } });
    },
    sendFile(id, bytes, options) {
      sentFiles.push({ id, bytes, options });
      return Promise.resolve({ file: { manifest: { fileId: 'f' }, rootKey: 'k' } });
    },
    receiveNext() {
      if (received.length) return Promise.resolve(received.shift());
      return Promise.reject(timeout);
    },
    receiveContactAccept(id, options) {
      acceptCalls.push({ id, options });
      return Promise.resolve({ contact: { id, state: 'active' } });
    },
    deleteContactEverywhere(id, options) {
      deleteCalls.push({ id, options });
      return Promise.resolve({ contact: { id, state: 'deleted' }, remoteDeletedQueues: [id + ':inbox'] });
    },
    deleteContact(id, options) {
      localDeleteCalls.push({ id, options });
      return { id, state: 'deleted' };
    }
  };
  var adapter = createSimplexWebTransportAdapter({ contactClient });
  assert.equal(adapter.getStatus().transport_status, 'direct-browser-smp');
  var receipt = await adapter.sendText({ contact_id: 'alice', text: 'hello', client_message_id: 'm1' });
  assert.equal(receipt.message_ref, 'm1');
  assert.equal(sentText[0].text, 'hello');

  var file = {
    name: 'notes.txt',
    type: 'text/plain',
    size: 5,
    arrayBuffer() {
      return Promise.resolve(new Uint8Array([1, 2, 3, 4, 5]).buffer);
    }
  };
  var fileReceipts = await adapter.sendFiles({ contact_id: 'alice', files: [file], client_message_id: 'f1', max_file_bytes: 10 });
  assert.equal(fileReceipts[0].attachment.name, 'notes.txt');
  assert.equal(sentFiles[0].bytes.length, 5);

  var messages = await adapter.getMessages({ contact_id: 'alice', limit: 2 });
  assert.equal(messages.length, 1);
  assert.equal(messages[0].text, 'reply');
  assert.equal(messages[0].delivery_status, 'received');
  assert.equal(messages[0].ack_pending, false);
  await adapter.receiveContactAccept({ contact_id: 'alice', ackCorrId: 'accept-ack' });
  assert.equal(acceptCalls[0].id, 'alice');
  assert.equal(acceptCalls[0].options.ackCorrId, 'accept-ack');
  var deleted = await adapter.deleteContact({ contact_id: 'alice', corr_id: 'delete-1' });
  assert.deepEqual(deleted.remoteDeletedQueues, ['alice:inbox']);
  assert.equal(deleteCalls[0].id, 'alice');
  assert.equal(deleteCalls[0].options.corrId, 'delete-1');
  var localDeleted = await adapter.deleteContact({ contact_id: 'alice', local_only: true, hard_delete: true });
  assert.equal(localDeleted.state, 'deleted');
  assert.equal(localDeleteCalls[0].id, 'alice');
  assert.equal(localDeleteCalls[0].options.localOnly, true);
  assert.equal(localDeleteCalls[0].options.hardDelete, true);

  var registered = registerSimplexWebTransportAdapter({ contactClient }, {
    registerBrowserTransport(nextAdapter) {
      assert.equal(typeof nextAdapter.sendText, 'function');
      return { registered: true };
    }
  });
  assert.deepEqual(registered, { registered: true });
});

test('SimplexWebTransport adapter sends and receives over the browser SimpleX contact client', async () => {
  var broker = new BrowserProfileBroker();
  var aliceStore = createBrowserSimplexStore({ namespace: 'adapter-alice' });
  var bobStore = createBrowserSimplexStore({ namespace: 'adapter-bob' });
  var alice = createSimplexWebTransportAdapter({ transport: broker.connect('alice'), store: aliceStore });
  var bob = createSimplexWebTransportAdapter({ transport: broker.connect('bob'), store: bobStore });
  await alice.connect();
  await bob.connect();
  await activateAdapterPair(alice, bob, aliceStore, bobStore);

  var sent = await alice.sendText({ contact_id: 'bob', text: 'hello bob', client_message_id: 'alice-msg-1' });
  assert.equal(sent.message_ref, 'alice-msg-1');
  var messages = await bob.getMessages({ contact_id: 'alice', limit: 1 });
  assert.equal(messages.length, 1);
  assert.equal(messages[0].text, 'hello bob');
  assert.equal(messages[0].message_kind, 'text');

  var allAcked = Array.from(broker.queues.values()).every((queue) => (
    Array.from(queue.messages.values()).every((message) => message.acked)
  ));
  assert.equal(allAcked, true);

  var bobInbox = bobStore.loadQueue('alice:inbox');
  var deleted = await bob.deleteContact({ contact_id: 'alice', corrId: 'bob-del' });
  assert.deepEqual(deleted.remoteDeletedQueues, ['alice:inbox']);
  assert.equal(broker.findByRecipientId(bobInbox.rcvId), null);
  assert.equal(bobStore.loadContact('alice').state, 'deleted');
  assert.equal(bobStore.loadQueue('alice:inbox'), null);
});
