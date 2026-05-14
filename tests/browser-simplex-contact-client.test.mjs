import test from 'node:test';
import assert from 'node:assert/strict';

import * as smp from '../src/browser-smp-core.mjs';
import {
  decryptClientMessageEnvelope,
  encryptRcvMessageBody,
  parseClientMessageEnvelope,
  parseNativeAgentEnvelope,
  prepareInitialSenderMessage,
  prepareNativeInvitationJoin
} from '../src/browser-simplex-agent.mjs';
import { createBrowserSimplexClient } from '../src/browser-simplex-client.mjs';
import { CONTACT_PAYLOAD_PREFIX, createBrowserSimplexContactClient, decodeContactPayload, encodeContactPayload } from '../src/browser-simplex-contact-client.mjs';
import { createBrowserSimplexStore, SIMPLEX_STORE_MAX_LIST_ITEMS } from '../src/browser-simplex-store.mjs';
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

function lastParsedCommand(transport, type) {
  for (let i = transport.sent.length - 1; i >= 0; i -= 1) {
    const parsed = smp.parseSignedTransmission(4, transport.sent[i].bytes);
    if (!type || parsed.command.type === type) return parsed;
  }
  throw new Error('no sent command found');
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
  const replyServerDh = smp.generateX25519KeyPair(filled(32, 73));

  transport.pushResponse('reply-new', {
    type: 'IDS',
    rcvId: filled(24, 74),
    sndId: filled(24, 75),
    rcvPublicDhKey: replyServerDh.publicKeyDer
  });
  transport.pushResponse('req-1', { type: 'OK' }, filled(24, 59));
  const contact = await contacts.requestContact('bob', invitationUri, {
    replyCorrId: 'reply-new',
    replyRcvSignSeed: filled(32, 76),
    replyRcvDhSeed: filled(32, 77),
    corrId: 'req-1',
    ownDhSeed: filled(32, 60),
    senderSignSeed: filled(32, 61),
    nonce: filled(24, 62),
    profile: { displayName: 'Alice' }
  });

  assert.equal(contact.state, 'requested');
  assert.equal(store.loadContact('bob').state, 'requested');
  assert.equal(store.loadQueue('bob:outbox').sndId.length, 24);
  assert.equal(store.loadQueue('bob:inbox').rcvId.length, 24);
  assert.ok(store.loadRatchet('bob').rootKey instanceof Uint8Array);
  const sent = smp.parseSignedTransmission(4, transport.sent[1].bytes);
  assert.equal(sent.command.type, 'SEND');
  assert.equal(sent.signature.length, 0);
  assert.equal(Buffer.from(sent.command.body).includes(Buffer.from('Alice')), false);
});

test('contact client rejects native SimpleX Chat invitations before side effects', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-native-invite' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 213)).publicKeyDer;
  const nativeQueue = smp.formatProtocolServer({
    scheme: 'smp',
    keyHash: filled(32, 214),
    host: 'smp.example.test',
    port: '5223'
  }) + '/' + smp.encodeBase64Url(filled(24, 215)) +
    '#/?v=1-4&dh=' + encodeURIComponent(smp.encodeBase64Url(recipientDh)) + '&q=m&k=s';
  const nativeX3dh = [
    smp.generateX448KeyPair(filled(56, 216)).publicKeyDer,
    smp.generateX448KeyPair(filled(56, 217)).publicKeyDer
  ].map(smp.encodeBase64Url).join(',');
  const nativeLink = 'simplex:/invitation#/?v=2-7&smp=' + encodeURIComponent(nativeQueue) +
    '&e2e=' + encodeURIComponent('v=2-3&x3dh=' + nativeX3dh);

  await assert.rejects(
    () => contacts.requestContact('bob', nativeLink, {
      replyCorrId: 'native-reply',
      corrId: 'native-req'
    }),
    /allowNativeAgentProfile/
  );
  assert.equal(store.loadContact('bob'), null);
  assert.equal(store.loadQueue('bob:inbox'), null);
  assert.equal(transport.sent.length, 0);
});

test('contact client can prepare and send a native SimpleX invitation join when explicitly enabled', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-native-join' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 223)).publicKeyDer;
  const nativeQueue = smp.formatProtocolServer({
    scheme: 'smp',
    keyHash: filled(32, 224),
    host: 'smp.example.test',
    port: '5223'
  }) + '/' + smp.encodeBase64Url(filled(24, 225)) +
    '#/?v=1-4&dh=' + encodeURIComponent(smp.encodeBase64Url(recipientDh)) + '&q=m&k=s';
  const nativeX3dh = [
    smp.generateX448KeyPair(filled(56, 226)).publicKeyDer,
    smp.generateX448KeyPair(filled(56, 227)).publicKeyDer
  ].map(smp.encodeBase64Url).join(',');
  const nativeLink = 'simplex:/invitation#/?v=2-7&smp=' + encodeURIComponent(nativeQueue) +
    '&e2e=' + encodeURIComponent('v=2-3&x3dh=' + nativeX3dh);
  const replyServerDh = smp.generateX25519KeyPair(filled(32, 228));
  transport.pushResponse('native-reply', {
    type: 'IDS',
    rcvId: filled(24, 229),
    sndId: filled(24, 230),
    rcvPublicDhKey: replyServerDh.publicKeyDer
  });
  transport.pushResponse('native-req', { type: 'OK' }, filled(24, 225));

  const contact = await contacts.requestContact('bob', nativeLink, {
    allowNativeAgentProfile: true,
    replyCorrId: 'native-reply',
    corrId: 'native-req',
    ownDhSeed: filled(32, 231),
    senderX3dhSeed1: filled(56, 232),
    senderX3dhSeed2: filled(56, 233),
    senderRatchetSeed: filled(56, 234),
    senderSignSeed: filled(32, 235),
    nonce: filled(24, 236),
    profile: { displayName: 'Browser' }
  });

  assert.equal(contact.state, 'requested');
  assert.equal(contact.nativeAgentProfile, true);
  assert.equal(store.loadQueue('bob:inbox').sndId.length, 24);
  assert.equal(store.loadQueue('bob:outbox').nativeRatchet.sendCount, 1);
  const sent = lastParsedCommand(transport, 'SEND');
  assert.equal(smp.equalBytes(sent.queueId, filled(24, 225)), true);
  assert.equal(Buffer.from(sent.command.body).includes(Buffer.from('Browser')), false);

  contact.state = 'active';
  store.saveContact('bob', contact);
  transport.pushResponse('native-send', { type: 'OK' }, filled(24, 225));
  await contacts.sendText('bob', 'hello Owl', {
    corrId: 'native-send',
    clientMessageId: 'native-msg'
  });
  const nativeMessage = lastParsedCommand(transport, 'SEND');
  assert.equal(smp.equalBytes(nativeMessage.queueId, filled(24, 225)), true);
  assert.equal(Buffer.from(nativeMessage.command.body).includes(Buffer.from('hello Owl')), false);
});

test('contact client requests native SimpleX contact addresses and activates after Owl accept', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport, transportForServer: async () => transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-native-address' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const contactQueueDh = smp.generateX25519KeyPair(filled(32, 237));
  const nativeQueue = smp.formatProtocolServer({
    scheme: 'smp',
    keyHash: filled(32, 238),
    host: 'smp.example.test',
    port: '5223'
  }) + '/' + smp.encodeBase64Url(filled(24, 239)) +
    '#/?v=1-4&dh=' + encodeURIComponent(smp.encodeBase64Url(contactQueueDh.publicKeyDer)) + '&q=c';
  const nativeLink = 'simplex:/contact#/?v=2-7&smp=' + encodeURIComponent(nativeQueue);
  const replyServerDh = smp.generateX25519KeyPair(filled(32, 240));
  transport.pushResponse('native-contact-reply', {
    type: 'IDS',
    rcvId: filled(24, 241),
    sndId: filled(24, 242),
    rcvPublicDhKey: replyServerDh.publicKeyDer
  });
  transport.pushResponse('native-contact-req', { type: 'OK' }, filled(24, 239));

  const contact = await contacts.requestContact('bob', nativeLink, {
    allowNativeAgentProfile: true,
    replyCorrId: 'native-contact-reply',
    corrId: 'native-contact-req',
    ownDhSeed: filled(32, 243),
    recipientX3dhSeed1: filled(56, 244),
    recipientX3dhSeed2: filled(56, 245),
    senderSignSeed: filled(32, 246),
    nonce: filled(24, 247),
    profile: { displayName: 'Browser' }
  });

  assert.equal(contact.state, 'requested');
  assert.equal(contact.nativeContactAddress, true);
  assert.equal(store.loadRatchet('bob').pendingNativeContactRequest, true);
  const requestCommand = lastParsedCommand(transport, 'SEND');
  const requestEnvelope = parseClientMessageEnvelope(requestCommand.command.body);
  const requestOuter = decryptClientMessageEnvelope({
    sharedSecret: smp.x25519SharedSecret(contactQueueDh.secretKey, smp.decodePublicKeyDer(requestEnvelope.publicHeader.e2ePubDhKey).rawPublicKey),
    envelope: requestCommand.command.body
  });
  assert.equal(requestOuter.privateHeader.type, 'empty');
  const requestNative = parseNativeAgentEnvelope(requestOuter.body);
  assert.equal(requestNative.type, 'invitation');
  assert.equal(Buffer.from(requestCommand.command.body).includes(Buffer.from('Browser')), false);

  const owlReplyQueue = {
    server: { scheme: 'smp', keyHash: filled(32, 248), host: 'smp.example.test', port: '5223' },
    sndId: filled(24, 249),
    rcvDhKey: smp.generateX25519KeyPair(filled(32, 250)),
    queueMode: 'm'
  };
  const preparedAccept = prepareNativeInvitationJoin({
    invitationUri: smp.utf8Text(requestNative.connReq),
    replyQueue: owlReplyQueue,
    ownDhSeed: filled(32, 251),
    senderX3dhSeed1: filled(56, 252),
    senderX3dhSeed2: filled(56, 253),
    senderRatchetSeed: filled(56, 254),
    senderSignSeed: filled(32, 255),
    nonce: filled(24, 256),
    profile: { displayName: 'Owl' }
  });
  const inbox = store.loadQueue('bob:inbox');
  const msgId = filled(24, 257);
  const body = encryptRcvMessageBody({
    serverDhSecret: inbox.serverDhSecret,
    msgId,
    timestamp: 1777n,
    body: preparedAccept.envelope
  });
  transport.pushResponse('native-accept-msg', { type: 'MSG', msgId, body }, inbox.rcvId);
  transport.pushResponse('native-accept-key', { type: 'OK' }, inbox.rcvId);
  transport.pushResponse('native-accept-skey', { type: 'OK' }, owlReplyQueue.sndId);
  transport.pushResponse('native-accept-hello', { type: 'OK' }, owlReplyQueue.sndId);
  transport.pushResponse('native-accept-ack', { type: 'OK' }, inbox.rcvId);

  const accepted = await contacts.receiveContactAccept('bob', {
    corrId: 'native-accept-msg',
    keyCorrId: 'native-accept-key',
    skeyCorrId: 'native-accept-skey',
    helloCorrId: 'native-accept-hello',
    ackCorrId: 'native-accept-ack'
  });
  assert.equal(accepted.contact.state, 'active');
  assert.equal(accepted.accept.profile.displayName, 'Owl');
  assert.equal(smp.equalBytes(store.loadContact('bob').outboundQueue.sndId, owlReplyQueue.sndId), true);

  transport.pushResponse('native-contact-send', { type: 'OK' }, owlReplyQueue.sndId);
  await contacts.sendText('bob', 'hello after accept', {
    corrId: 'native-contact-send',
    clientMessageId: 'native-contact-msg',
    ownDhSeed: filled(56, 258)
  });
  const sentMessage = lastParsedCommand(transport, 'SEND');
  assert.equal(smp.equalBytes(sentMessage.queueId, owlReplyQueue.sndId), true);
  assert.equal(Buffer.from(sentMessage.command.body).includes(Buffer.from('hello after accept')), false);
});

test('contact client retries failed contact requests without storing plaintext profile data', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-request-retry' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 193));
  const invitationUri = smp.formatSmpQueueUri({
    server: { scheme: 'smp', keyHash: filled(32, 194), host: 'smp.example.test', port: '5223' },
    queueId: filled(24, 195),
    recipientDhPublicKey: recipientDh.publicKeyDer
  });
  const replyServerDh = smp.generateX25519KeyPair(filled(32, 196));

  transport.pushResponse('reply-new-retry', {
    type: 'IDS',
    rcvId: filled(24, 197),
    sndId: filled(24, 198),
    rcvPublicDhKey: replyServerDh.publicKeyDer
  });

  await assert.rejects(() => contacts.requestContact('bob', invitationUri, {
    replyCorrId: 'reply-new-retry',
    replyRcvSignSeed: filled(32, 199),
    replyRcvDhSeed: filled(32, 200),
    corrId: 'req-pending',
    ownDhSeed: filled(32, 201),
    senderSignSeed: filled(32, 202),
    nonce: filled(24, 203),
    profile: { displayName: 'Alice Secret' }
  }), /no fake responses/);

  const pending = store.listPending()[0];
  assert.equal(store.loadContact('bob').state, 'requested');
  assert.equal(store.loadQueue('bob:inbox').rcvId.length, 24);
  assert.equal(store.loadQueue('bob:outbox').sndId.length, 24);
  assert.equal(store.loadRatchet('bob').rootKey.length, 32);
  assert.equal(pending.payload.type, 'initialConfirmation');
  assert.equal(JSON.stringify(pending).includes('Alice Secret'), false);
  assert.equal(JSON.stringify(pending).includes('contact-request'), false);

  const originalRequest = smp.parseSignedTransmission(4, transport.sent[1].bytes);
  transport.pushResponse('req-pending', { type: 'OK' }, filled(24, 195));
  const retried = await contacts.drainDueRetries({ now: Date.now() + 60000 });

  assert.equal(retried.length, 1);
  assert.equal(retried[0].ok, true);
  assert.equal(store.listPending()[0].completedAt > 0, true);
  const retryRequest = smp.parseSignedTransmission(4, transport.sent[2].bytes);
  assert.equal(smp.equalBytes(originalRequest.command.body, retryRequest.command.body), true);
  assert.equal(Buffer.from(retryRequest.command.body).includes(Buffer.from('Alice Secret')), false);
});

test('contact client persists caller supplied requester reply queue', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-request-supplied-reply' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 136));
  const invitationUri = smp.formatSmpQueueUri({
    server: { scheme: 'smp', keyHash: filled(32, 137), host: 'smp.example.test', port: '5223' },
    queueId: filled(24, 138),
    recipientDhPublicKey: recipientDh.publicKeyDer
  });
  const replyQueue = {
    server: { scheme: 'smp', keyHash: filled(32, 139), host: 'smp.example.test', port: '5223' },
    rcvId: filled(24, 140),
    sndId: filled(24, 141),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 142)),
    rcvDhKey: smp.generateX25519KeyPair(filled(32, 143)),
    serverDhSecret: filled(32, 144)
  };

  transport.pushResponse('req-supplied', { type: 'OK' }, filled(24, 138));
  await contacts.requestContact('bob', invitationUri, {
    replyQueue,
    corrId: 'req-supplied',
    ownDhSeed: filled(32, 145),
    senderSignSeed: filled(32, 146),
    nonce: filled(24, 147),
    profile: { displayName: 'Alice' }
  });

  assert.equal(smp.equalBytes(store.loadQueue('bob:inbox').rcvId, replyQueue.rcvId), true);
  assert.equal(store.loadContact('bob').inboxQueueId, 'bob:inbox');
});

test('contact client receives contact request secures queue and stores receiving ratchet', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-accept' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 63));
  const senderDh = smp.generateX25519KeyPair(filled(32, 64));
  const replyDh = smp.generateX25519KeyPair(filled(32, 73));
  const replyQueueId = filled(24, 74);
  const replyQueueUri = smp.formatSmpQueueUri({
    server: { scheme: 'smp', keyHash: filled(32, 75), host: 'smp.example.test', port: '5223' },
    queueId: replyQueueId,
    recipientDhPublicKey: replyDh.publicKeyDer
  });
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
    body: smp.utf8Bytes(JSON.stringify({ type: 'contact-request', profile: { displayName: 'Bob' }, replyQueueUri }))
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
  transport.pushResponse('accept-1', { type: 'OK' }, replyQueueId);

  const accepted = await contacts.receiveContactRequest('alice', {
    keyCorrId: 'key-1',
    ackCorrId: 'ack-2',
    acceptCorrId: 'accept-1',
    acceptDhSeed: filled(32, 76),
    acceptSenderSignSeed: filled(32, 77),
    acceptNonce: filled(24, 78)
  });
  assert.equal(accepted.contact.state, 'active');
  assert.equal(accepted.accept.response.message.type, 'OK');
  assert.equal(accepted.request.profile.displayName, 'Bob');
  assert.equal(accepted.timestamp, 789n);
  assert.equal(store.loadContact('alice').remoteProfile.displayName, 'Bob');
  assert.equal(smp.equalBytes(store.loadContact('alice').outboundQueue.sndId, replyQueueId), true);
  assert.ok(store.loadRatchet('alice').rootKey instanceof Uint8Array);
  const keyCommand = smp.parseSignedTransmission(4, transport.sent[0].bytes).command;
  const ackCommand = smp.parseSignedTransmission(4, transport.sent[1].bytes).command;
  const acceptCommand = smp.parseSignedTransmission(4, transport.sent[2].bytes).command;
  assert.equal(keyCommand.type, 'KEY');
  assert.equal(ackCommand.type, 'ACK');
  assert.equal(acceptCommand.type, 'SEND');
  assert.equal(smp.equalBytes(ackCommand.msgId, msgId), true);
});

test('contact client retries failed accept confirmations after saving active contact state', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-accept-retry' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 204));
  const senderDh = smp.generateX25519KeyPair(filled(32, 205));
  const replyDh = smp.generateX25519KeyPair(filled(32, 206));
  const replyQueueId = filled(24, 207);
  const replyQueueUri = smp.formatSmpQueueUri({
    server: { scheme: 'smp', keyHash: filled(32, 208), host: 'smp.example.test', port: '5223' },
    queueId: replyQueueId,
    recipientDhPublicKey: replyDh.publicKeyDer
  });
  const shared = smp.x25519SharedSecret(senderDh.secretKey, recipientDh.publicKey);
  const queue = {
    rcvId: filled(24, 209),
    sndId: filled(24, 210),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 211)),
    rcvDhKey: recipientDh,
    serverDhSecret: filled(32, 212)
  };
  store.saveContact('alice', { id: 'alice', state: 'invited', inboxQueueId: 'alice:inbox', profile: { displayName: 'Local' } });
  store.saveQueue('alice:inbox', queue);

  const prepared = prepareInitialSenderMessage({
    version: 4,
    sessionId: transport.sessionId,
    corrId: smp.asciiBytes('initial-retry'),
    senderQueueId: queue.sndId,
    senderSignSeed: filled(32, 213),
    e2eSharedSecret: shared,
    senderE2ePubDhKey: senderDh.publicKeyDer,
    nonce: filled(24, 214),
    body: smp.utf8Bytes(JSON.stringify({ type: 'contact-request', profile: { displayName: 'Bob' }, replyQueueUri }))
  });
  const msgId = filled(24, 215);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 790n,
    body: prepared.envelope
  });
  transport.pushResponse('msg-request-retry', { type: 'MSG', msgId, body }, queue.rcvId);
  transport.pushResponse('key-retry', { type: 'OK' }, queue.rcvId);
  transport.pushResponse('ack-retry', { type: 'OK' }, queue.rcvId);

  await assert.rejects(() => contacts.receiveContactRequest('alice', {
    keyCorrId: 'key-retry',
    ackCorrId: 'ack-retry',
    acceptCorrId: 'accept-pending',
    acceptDhSeed: filled(32, 216),
    acceptSenderSignSeed: filled(32, 217),
    acceptNonce: filled(24, 218),
    acceptProfile: { displayName: 'Alice Secret' }
  }), /no fake responses/);

  const contact = store.loadContact('alice');
  const pending = store.listPending()[0];
  assert.equal(contact.state, 'active');
  assert.equal(store.loadQueue('alice:outbox').sndId.length, 24);
  assert.equal(store.loadRatchet('alice').rootKey.length, 32);
  assert.equal(pending.payload.type, 'initialConfirmation');
  assert.equal(pending.payload.transmission instanceof Uint8Array, true);
  assert.equal(JSON.stringify(pending).includes('Alice Secret'), false);

  const originalAccept = smp.parseSignedTransmission(4, transport.sent[2].bytes);
  transport.pushResponse('accept-pending', { type: 'OK' }, replyQueueId);
  const retried = await contacts.drainDueRetries({ now: Date.now() + 60000 });

  assert.equal(retried.length, 1);
  assert.equal(retried[0].ok, true);
  assert.equal(store.listPending()[0].completedAt > 0, true);
  const retryAccept = smp.parseSignedTransmission(4, transport.sent[3].bytes);
  assert.equal(smp.equalBytes(originalAccept.command.body, retryAccept.command.body), true);
  assert.equal(Buffer.from(retryAccept.command.body).includes(Buffer.from('Alice Secret')), false);
});

test('contact client saves request state sends accept and retries ACK after request ack failure', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-request-ack-retry' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 230));
  const senderDh = smp.generateX25519KeyPair(filled(32, 231));
  const replyDh = smp.generateX25519KeyPair(filled(32, 232));
  const replyQueueId = filled(24, 233);
  const replyQueueUri = smp.formatSmpQueueUri({
    server: { scheme: 'smp', keyHash: filled(32, 234), host: 'smp.example.test', port: '5223' },
    queueId: replyQueueId,
    recipientDhPublicKey: replyDh.publicKeyDer
  });
  const shared = smp.x25519SharedSecret(senderDh.secretKey, recipientDh.publicKey);
  const queue = {
    rcvId: filled(24, 235),
    sndId: filled(24, 236),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 237)),
    rcvDhKey: recipientDh,
    serverDhSecret: filled(32, 238)
  };
  store.saveContact('alice', { id: 'alice', state: 'invited', inboxQueueId: 'alice:inbox' });
  store.saveQueue('alice:inbox', queue);

  const prepared = prepareInitialSenderMessage({
    version: 4,
    sessionId: transport.sessionId,
    corrId: smp.asciiBytes('request-ack-retry'),
    senderQueueId: queue.sndId,
    senderSignSeed: filled(32, 239),
    e2eSharedSecret: shared,
    senderE2ePubDhKey: senderDh.publicKeyDer,
    nonce: filled(24, 240),
    body: smp.utf8Bytes(JSON.stringify({ type: 'contact-request', profile: { displayName: 'Bob' }, replyQueueUri }))
  });
  const msgId = filled(24, 241);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 791n,
    body: prepared.envelope
  });
  transport.pushResponse('msg-request-ack-retry', { type: 'MSG', msgId, body }, queue.rcvId);
  transport.pushResponse('key-request-ack-retry', { type: 'OK' }, queue.rcvId);
  transport.pushResponse('accept-after-ack-pending', { type: 'OK' }, replyQueueId);

  const accepted = await contacts.receiveContactRequest('alice', {
    keyCorrId: 'key-request-ack-retry',
    ackCorrId: 'ack-request-missing',
    acceptCorrId: 'accept-after-ack-pending',
    acceptDhSeed: filled(32, 242),
    acceptSenderSignSeed: filled(32, 243),
    acceptNonce: filled(24, 244)
  });

  assert.equal(accepted.contact.state, 'active');
  assert.equal(accepted.acknowledged, false);
  assert.equal(accepted.ackPending, true);
  assert.equal(accepted.accept.response.message.type, 'OK');
  assert.equal(store.loadContact('alice').state, 'active');
  assert.equal(store.loadRatchet('alice').rootKey.length, 32);
  assert.equal(store.listPending()[0].payload.type, 'ackMessage');

  transport.pushResponse('request-ack-retry-ok', { type: 'OK' }, queue.rcvId);
  const retried = await contacts.drainDueRetries({
    now: Date.now() + 60000,
    ackOptions: { corrId: 'request-ack-retry-ok' }
  });
  assert.equal(retried.length, 1);
  assert.equal(retried[0].ok, true);
  const retryAck = smp.parseSignedTransmission(4, transport.sent[3].bytes);
  assert.equal(retryAck.command.type, 'ACK');
  assert.equal(smp.equalBytes(retryAck.command.msgId, msgId), true);
});

test('contact client rejects malformed reply queue before request side effects', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-bad-reply-queue' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 148));
  const senderDh = smp.generateX25519KeyPair(filled(32, 149));
  const shared = smp.x25519SharedSecret(senderDh.secretKey, recipientDh.publicKey);
  const queue = {
    rcvId: filled(24, 150),
    sndId: filled(24, 151),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 152)),
    rcvDhKey: recipientDh,
    serverDhSecret: filled(32, 153)
  };
  store.saveContact('alice', { id: 'alice', state: 'invited', inboxQueueId: 'alice:inbox' });
  store.saveQueue('alice:inbox', queue);

  const prepared = prepareInitialSenderMessage({
    version: 4,
    sessionId: transport.sessionId,
    corrId: smp.asciiBytes('bad-reply'),
    senderQueueId: queue.sndId,
    senderSignSeed: filled(32, 154),
    e2eSharedSecret: shared,
    senderE2ePubDhKey: senderDh.publicKeyDer,
    nonce: filled(24, 155),
    body: smp.utf8Bytes(JSON.stringify({
      type: 'contact-request',
      profile: { displayName: 'Mallory' },
      replyQueueUri: 'smp://not a valid reply queue'
    }))
  });
  const msgId = filled(24, 156);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 222n,
    body: prepared.envelope
  });
  transport.pushResponse('bad-reply-msg', { type: 'MSG', msgId, body }, queue.rcvId);

  await assert.rejects(() => contacts.receiveContactRequest('alice', {
    keyCorrId: 'bad-reply-key',
    ackCorrId: 'bad-reply-ack',
    acceptCorrId: 'bad-reply-accept'
  }), /queue uri|unsupported/i);
  assert.equal(transport.sent.length, 0);
  assert.equal(store.loadContact('alice').state, 'invited');
});

test('contact client receives accept confirmation and secures requester reply queue', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-accept-confirmation' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 91));
  const senderDh = smp.generateX25519KeyPair(filled(32, 92));
  const shared = smp.x25519SharedSecret(senderDh.secretKey, recipientDh.publicKey);
  const queue = {
    rcvId: filled(24, 93),
    sndId: filled(24, 94),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 95)),
    rcvDhKey: recipientDh,
    serverDhSecret: filled(32, 96)
  };
  const outbox = {
    sndId: filled(24, 97),
    senderSignKey: smp.generateEd25519KeyPair(filled(32, 98))
  };
  store.saveContact('alice', {
    id: 'alice',
    state: 'requested',
    inboxQueueId: 'alice:inbox',
    outboundQueue: outbox
  });
  store.saveQueue('alice:inbox', queue);
  store.saveQueue('alice:outbox', outbox);
  store.saveRatchet('alice', {
    rootKey: filled(32, 99),
    ownDhKey: smp.generateX25519KeyPair(filled(32, 100)),
    remoteDhPublicKey: smp.generateX25519KeyPair(filled(32, 101)).publicKey,
    sendingChainKey: filled(32, 102)
  });

  const prepared = prepareInitialSenderMessage({
    version: 4,
    sessionId: transport.sessionId,
    corrId: smp.asciiBytes('accept'),
    senderQueueId: queue.sndId,
    senderSignSeed: filled(32, 103),
    e2eSharedSecret: shared,
    senderE2ePubDhKey: senderDh.publicKeyDer,
    nonce: filled(24, 104),
    body: smp.utf8Bytes(JSON.stringify({ type: 'contact-accept', profile: { displayName: 'Alice' } }))
  });
  const msgId = filled(24, 105);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 987n,
    body: prepared.envelope
  });
  transport.pushResponse('accept-msg', { type: 'MSG', msgId, body }, queue.rcvId);
  transport.pushResponse('accept-key', { type: 'OK' }, queue.rcvId);
  transport.pushResponse('accept-ack', { type: 'OK' }, queue.rcvId);

  const accepted = await contacts.receiveContactAccept('alice', {
    keyCorrId: 'accept-key',
    ackCorrId: 'accept-ack'
  });
  assert.equal(accepted.contact.state, 'active');
  assert.equal(accepted.accept.profile.displayName, 'Alice');
  assert.equal(accepted.timestamp, 987n);
  assert.equal(store.loadContact('alice').remoteProfile.displayName, 'Alice');
  assert.equal(store.loadQueue('alice:outbox').sndId.length, 24);
  const keyCommand = smp.parseSignedTransmission(4, transport.sent[0].bytes).command;
  const ackCommand = smp.parseSignedTransmission(4, transport.sent[1].bytes).command;
  assert.equal(keyCommand.type, 'KEY');
  assert.equal(ackCommand.type, 'ACK');
  assert.equal(smp.equalBytes(ackCommand.msgId, msgId), true);
});

test('contact client keeps accept confirmation state and retries ACK after ack transport failure', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-accept-ack-retry' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 219));
  const senderDh = smp.generateX25519KeyPair(filled(32, 220));
  const shared = smp.x25519SharedSecret(senderDh.secretKey, recipientDh.publicKey);
  const queue = {
    rcvId: filled(24, 221),
    sndId: filled(24, 222),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 223)),
    rcvDhKey: recipientDh,
    serverDhSecret: filled(32, 224)
  };
  const outbox = {
    sndId: filled(24, 225),
    senderSignKey: smp.generateEd25519KeyPair(filled(32, 226))
  };
  store.saveContact('alice', {
    id: 'alice',
    state: 'requested',
    inboxQueueId: 'alice:inbox',
    outboundQueue: outbox
  });
  store.saveQueue('alice:inbox', queue);
  store.saveQueue('alice:outbox', outbox);

  const prepared = prepareInitialSenderMessage({
    version: 4,
    sessionId: transport.sessionId,
    corrId: smp.asciiBytes('accept-ack-retry'),
    senderQueueId: queue.sndId,
    senderSignSeed: filled(32, 227),
    e2eSharedSecret: shared,
    senderE2ePubDhKey: senderDh.publicKeyDer,
    nonce: filled(24, 228),
    body: smp.utf8Bytes(JSON.stringify({ type: 'contact-accept', profile: { displayName: 'Alice Secret' } }))
  });
  const msgId = filled(24, 229);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 988n,
    body: prepared.envelope
  });
  transport.pushResponse('accept-ack-msg', { type: 'MSG', msgId, body }, queue.rcvId);
  transport.pushResponse('accept-key-ok', { type: 'OK' }, queue.rcvId);

  const accepted = await contacts.receiveContactAccept('alice', {
    keyCorrId: 'accept-key-ok',
    ackCorrId: 'accept-ack-missing'
  });

  assert.equal(accepted.contact.state, 'active');
  assert.equal(accepted.acknowledged, false);
  assert.equal(accepted.ackPending, true);
  assert.equal(store.loadContact('alice').remoteProfile.displayName, 'Alice Secret');
  assert.equal(store.listPending()[0].payload.type, 'ackMessage');
  assert.equal(JSON.stringify(store.listPending()[0]).includes('Alice Secret'), false);

  transport.pushResponse('accept-ack-retry-ok', { type: 'OK' }, queue.rcvId);
  const retried = await contacts.drainDueRetries({
    now: Date.now() + 60000,
    ackOptions: { corrId: 'accept-ack-retry-ok' }
  });
  assert.equal(retried.length, 1);
  assert.equal(retried[0].ok, true);
  assert.equal(store.listPending()[0].completedAt > 0, true);
  const retryAck = smp.parseSignedTransmission(4, transport.sent[2].bytes);
  assert.equal(retryAck.command.type, 'ACK');
  assert.equal(smp.equalBytes(retryAck.command.msgId, msgId), true);
});

test('accepted contact can receive the requester first ratcheted message', async () => {
  const transport = new FakeTransport();
  const aliceClient = createBrowserSimplexClient({ transport });
  const bobClient = createBrowserSimplexClient({ transport });
  const aliceStore = createBrowserSimplexStore({ namespace: 'contacts-full-handshake-alice' });
  const bobStore = createBrowserSimplexStore({ namespace: 'contacts-full-handshake-bob' });
  const aliceContacts = createBrowserSimplexContactClient({ client: aliceClient, store: aliceStore });
  const bobContacts = createBrowserSimplexContactClient({ client: bobClient, store: bobStore });
  const bobServerDh = smp.generateX25519KeyPair(filled(32, 115));

  transport.pushResponse('bob-new', {
    type: 'IDS',
    rcvId: filled(24, 116),
    sndId: filled(24, 117),
    rcvPublicDhKey: bobServerDh.publicKeyDer
  });
  const bobInvite = await bobContacts.createInvitation({
    id: 'alice',
    corrId: 'bob-new',
    server: { scheme: 'smp', keyHash: filled(32, 118), host: 'smp.example.test', port: '5223' },
    rcvSignSeed: filled(32, 119),
    rcvDhSeed: filled(32, 120)
  });

  const aliceReplyServerDh = smp.generateX25519KeyPair(filled(32, 121));
  transport.pushResponse('alice-reply-new', {
    type: 'IDS',
    rcvId: filled(24, 122),
    sndId: filled(24, 123),
    rcvPublicDhKey: aliceReplyServerDh.publicKeyDer
  });
  transport.pushResponse('alice-request', { type: 'OK' }, filled(24, 117));
  await aliceContacts.requestContact('bob', bobInvite.invitationUri, {
    replyCorrId: 'alice-reply-new',
    replyRcvSignSeed: filled(32, 124),
    replyRcvDhSeed: filled(32, 125),
    corrId: 'alice-request',
    ownDhSeed: filled(32, 126),
    senderSignSeed: filled(32, 127),
    nonce: filled(24, 128),
    profile: { displayName: 'Alice' }
  });

  const requestCommand = lastParsedCommand(transport, 'SEND').command;
  const bobInbox = bobStore.loadQueue('alice:inbox');
  const requestMsgId = filled(24, 129);
  transport.pushResponse('request-msg', {
    type: 'MSG',
    msgId: requestMsgId,
    body: encryptRcvMessageBody({
      serverDhSecret: bobInbox.serverDhSecret,
      msgId: requestMsgId,
      timestamp: 111n,
      body: requestCommand.body
    })
  }, bobInbox.rcvId);
  transport.pushResponse('bob-key', { type: 'OK' }, bobInbox.rcvId);
  transport.pushResponse('bob-ack', { type: 'OK' }, bobInbox.rcvId);
  transport.pushResponse('bob-accept', { type: 'OK' }, aliceStore.loadQueue('bob:inbox').sndId);
  await bobContacts.receiveContactRequest('alice', {
    keyCorrId: 'bob-key',
    ackCorrId: 'bob-ack',
    acceptCorrId: 'bob-accept',
    acceptDhSeed: filled(32, 130),
    acceptSenderSignSeed: filled(32, 131),
    acceptNonce: filled(24, 132)
  });

  const acceptCommand = lastParsedCommand(transport, 'SEND').command;
  const aliceInbox = aliceStore.loadQueue('bob:inbox');
  const acceptMsgId = filled(24, 133);
  transport.pushResponse('accept-msg', {
    type: 'MSG',
    msgId: acceptMsgId,
    body: encryptRcvMessageBody({
      serverDhSecret: aliceInbox.serverDhSecret,
      msgId: acceptMsgId,
      timestamp: 222n,
      body: acceptCommand.body
    })
  }, aliceInbox.rcvId);
  transport.pushResponse('alice-accept-key', { type: 'OK' }, aliceInbox.rcvId);
  transport.pushResponse('alice-accept-ack', { type: 'OK' }, aliceInbox.rcvId);
  await aliceContacts.receiveContactAccept('bob', {
    keyCorrId: 'alice-accept-key',
    ackCorrId: 'alice-accept-ack'
  });

  transport.pushResponse('first-text', { type: 'OK' }, filled(24, 117));
  await aliceContacts.sendText('bob', 'first encrypted hello', {
    corrId: 'first-text',
    clientMessageId: 'alice-first-1',
    nonce: filled(24, 134)
  });
  const firstTextCommand = lastParsedCommand(transport, 'SEND').command;
  const firstMsgId = filled(24, 135);
  transport.pushResponse('first-text-msg', {
    type: 'MSG',
    msgId: firstMsgId,
    body: encryptRcvMessageBody({
      serverDhSecret: bobInbox.serverDhSecret,
      msgId: firstMsgId,
      timestamp: 333n,
      body: firstTextCommand.body
    })
  }, bobInbox.rcvId);
  transport.pushResponse('first-text-ack', { type: 'OK' }, bobInbox.rcvId);

  const received = await bobContacts.receiveNext('alice', { ackCorrId: 'first-text-ack' });
  assert.equal(received.text, 'first encrypted hello');
  assert.equal(received.payload.messageRef, 'alice-first-1');
  assert.equal(received.timestamp, 333n);
});

test('contact client sends and receives encrypted read receipts', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-read-receipt' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const senderRatchet = createRatchetState({
    rootKey: filled(32, 154),
    ownDhKey: smp.generateX25519KeyPair(filled(32, 155)),
    remoteDhPublicKey: smp.generateX25519KeyPair(filled(32, 156)).publicKey
  });
  const receiverRatchet = createRatchetState({
    rootKey: filled(32, 154),
    ownDhKey: smp.generateX25519KeyPair(filled(32, 156)),
    initializeSending: false
  });
  const outbox = {
    sndId: filled(24, 157),
    senderSignKey: smp.generateEd25519KeyPair(filled(32, 158))
  };
  const inbox = {
    rcvId: filled(24, 159),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 160)),
    serverDhSecret: filled(32, 161)
  };
  store.saveContact('alice', {
    id: 'alice',
    state: 'active',
    inboxQueueId: 'alice:inbox',
    outboundQueue: outbox
  });
  store.saveQueue('alice:inbox', inbox);
  store.saveRatchet('alice', senderRatchet);

  transport.pushResponse('read-send', { type: 'OK' }, outbox.sndId);
  await contacts.sendReadReceipt('alice', 'sender-msg-1', {
    corrId: 'read-send',
    clientMessageId: 'read-local-1',
    nonce: filled(24, 162),
    readAt: '2026-05-12T00:00:00.000Z'
  });
  const sent = lastParsedCommand(transport, 'SEND');
  assert.equal(sent.command.type, 'SEND');
  assert.equal(Buffer.from(sent.command.body).includes(Buffer.from('sender-msg-1')), false);
  assert.equal(Buffer.from(sent.command.body).includes(Buffer.from('read-receipt')), false);

  store.saveRatchet('alice', receiverRatchet);
  const packet = encryptRatchetMessage(senderRatchet, smp.utf8Bytes(encodeContactPayload({
    type: 'read-receipt',
    messageRef: 'sender-msg-2',
    readAt: '2026-05-12T00:01:00.000Z'
  })), { nonce: filled(24, 163) }).packet;
  const msgId = filled(24, 164);
  const body = encryptRcvMessageBody({
    serverDhSecret: inbox.serverDhSecret,
    msgId,
    timestamp: 999n,
    body: packetBytes(packet)
  });
  transport.pushResponse('read-msg', { type: 'MSG', msgId, body }, inbox.rcvId);
  transport.pushResponse('read-ack', { type: 'OK' }, inbox.rcvId);

  const received = await contacts.receiveNext('alice', { ackCorrId: 'read-ack' });
  assert.equal(received.text, '');
  assert.equal(received.payload.type, 'read-receipt');
  assert.equal(received.payload.messageRef, 'sender-msg-2');
  assert.equal(received.payload.readAt, '2026-05-12T00:01:00.000Z');
});

test('contact client rejects malformed accept confirmation before queue side effects', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-bad-accept' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const recipientDh = smp.generateX25519KeyPair(filled(32, 106));
  const senderDh = smp.generateX25519KeyPair(filled(32, 107));
  const shared = smp.x25519SharedSecret(senderDh.secretKey, recipientDh.publicKey);
  const queue = {
    rcvId: filled(24, 108),
    sndId: filled(24, 109),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 110)),
    rcvDhKey: recipientDh,
    serverDhSecret: filled(32, 111)
  };
  store.saveContact('alice', { id: 'alice', state: 'requested', inboxQueueId: 'alice:inbox' });
  store.saveQueue('alice:inbox', queue);

  const prepared = prepareInitialSenderMessage({
    version: 4,
    sessionId: transport.sessionId,
    corrId: smp.asciiBytes('bad-accept'),
    senderQueueId: queue.sndId,
    senderSignSeed: filled(32, 112),
    e2eSharedSecret: shared,
    senderE2ePubDhKey: senderDh.publicKeyDer,
    nonce: filled(24, 113),
    body: smp.utf8Bytes(JSON.stringify({ type: 'contact-request' }))
  });
  const msgId = filled(24, 114);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 654n,
    body: prepared.envelope
  });
  transport.pushResponse('bad-accept-msg', { type: 'MSG', msgId, body }, queue.rcvId);

  await assert.rejects(() => contacts.receiveContactAccept('alice', {
    keyCorrId: 'bad-accept-key',
    ackCorrId: 'bad-accept-ack'
  }), /accept payload/i);
  assert.equal(transport.sent.length, 0);
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
  const pending = store.listPending()[0];
  assert.equal(store.listPending().length, 1);
  assert.equal(pending.payload.type, 'sendPacket');
  assert.equal(pending.payload.contactId, 'alice');
  assert.equal(JSON.stringify(pending).includes('retry me'), false);
  const sent = smp.parseSignedTransmission(4, transport.sent[0].bytes);
  assert.equal(pending.payload.packet instanceof Uint8Array, true);
  assert.equal(smp.equalBytes(sent.command.body, pending.payload.packet), true);
});

test('contact client does not advance ratchet when outbound queue is missing', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-missing-send-queue' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  store.saveContact('alice', { id: 'alice', state: 'active' });
  store.saveRatchet('alice', {
    rootKey: filled(32, 189),
    ownDhKey: smp.generateX25519KeyPair(filled(32, 190)),
    remoteDhPublicKey: smp.generateX25519KeyPair(filled(32, 191)).publicKey,
    sendingChainKey: filled(32, 192),
    sendCount: 0
  });

  await assert.rejects(() => contacts.sendText('alice', 'should not consume a ratchet step'), /outbound queue/i);

  assert.equal(store.loadRatchet('alice').sendCount, 0);
  assert.equal(store.listPending().length, 0);
  assert.equal(transport.sent.length, 0);
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

test('contact client keeps decrypted message and retries ACK after ack transport failure', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-ack-retry' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const aliceDh = smp.generateX25519KeyPair(filled(32, 157));
  const bobDh = smp.generateX25519KeyPair(filled(32, 158));
  const root = filled(32, 159);
  const senderRatchet = createRatchetState({ rootKey: root, ownDhKey: aliceDh, remoteDhPublicKey: bobDh.publicKey });
  const receiverRatchet = createRatchetState({ rootKey: root, ownDhKey: bobDh, initializeSending: false });
  const queue = {
    rcvId: filled(24, 160),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 161)),
    serverDhSecret: filled(32, 162)
  };
  store.saveContact('alice', { id: 'alice', state: 'active', inboxQueueId: 'alice:inbox' });
  store.saveQueue('alice:inbox', queue);
  store.saveRatchet('alice', receiverRatchet);

  const packet = encryptRatchetMessage(senderRatchet, smp.utf8Bytes('ack me later'), { nonce: filled(24, 163) }).packet;
  const msgId = filled(24, 164);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 777n,
    body: packetBytes(packet)
  });
  transport.pushResponse('msg-ack-retry', { type: 'MSG', msgId, body }, queue.rcvId);

  const received = await contacts.receiveNext('alice', { ackCorrId: 'missing-ack' });
  assert.equal(received.text, 'ack me later');
  assert.equal(received.acknowledged, false);
  assert.equal(received.ackPending, true);
  assert.equal(store.listPending().length, 1);
  assert.equal(store.listPending()[0].payload.type, 'ackMessage');
  assert.equal(store.listPending()[0].payload.contactId, 'alice');
  assert.equal(JSON.stringify(store.listPending()[0]).includes('ack me later'), false);

  transport.pushResponse('ack-retry-ok', { type: 'OK' }, queue.rcvId);
  const retried = await contacts.drainDueRetries({
    now: Date.now() + 60000,
    ackOptions: { corrId: 'ack-retry-ok' }
  });
  assert.equal(retried.length, 1);
  assert.equal(retried[0].ok, true);
  assert.equal(store.listPending()[0].completedAt > 0, true);
  const retryAck = smp.parseSignedTransmission(4, transport.sent[1].bytes);
  assert.equal(retryAck.command.type, 'ACK');
  assert.equal(smp.equalBytes(retryAck.command.msgId, msgId), true);
});

test('contact client ACKs duplicate received message ids without redelivering plaintext', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-replay-ack' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const aliceDh = smp.generateX25519KeyPair(filled(32, 165));
  const bobDh = smp.generateX25519KeyPair(filled(32, 166));
  const root = filled(32, 167);
  const senderRatchet = createRatchetState({ rootKey: root, ownDhKey: aliceDh, remoteDhPublicKey: bobDh.publicKey });
  const receiverRatchet = createRatchetState({ rootKey: root, ownDhKey: bobDh, initializeSending: false });
  const queue = {
    rcvId: filled(24, 168),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 169)),
    serverDhSecret: filled(32, 170)
  };
  store.saveContact('alice', { id: 'alice', state: 'active', inboxQueueId: 'alice:inbox' });
  store.saveQueue('alice:inbox', queue);
  store.saveRatchet('alice', receiverRatchet);

  const packet = encryptRatchetMessage(senderRatchet, smp.utf8Bytes('deliver once'), { nonce: filled(24, 171) }).packet;
  const msgId = filled(24, 172);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 778n,
    body: packetBytes(packet)
  });
  transport.pushResponse('msg-first', { type: 'MSG', msgId, body }, queue.rcvId);
  transport.pushResponse('ack-first', { type: 'OK' }, queue.rcvId);
  const first = await contacts.receiveNext('alice', { ackCorrId: 'ack-first' });
  assert.equal(first.text, 'deliver once');

  transport.pushResponse('msg-duplicate', { type: 'MSG', msgId, body }, queue.rcvId);
  transport.pushResponse('ack-duplicate', { type: 'OK' }, queue.rcvId);
  const duplicate = await contacts.receiveNext('alice', { ackCorrId: 'ack-duplicate' });
  assert.equal(duplicate.duplicate, true);
  assert.equal(duplicate.text, '');
  assert.equal(duplicate.payload.type, 'duplicate');
  assert.equal(duplicate.acknowledged, true);
  assert.equal(JSON.stringify(store.list('received'), (_key, value) => (
    typeof value === 'bigint' ? String(value) : value
  )).includes('deliver once'), false);
  const duplicateAck = smp.parseSignedTransmission(4, transport.sent[1].bytes);
  assert.equal(duplicateAck.command.type, 'ACK');
  assert.equal(smp.equalBytes(duplicateAck.command.msgId, msgId), true);
});

test('contact client rejects changed-body replay before ACK side effects', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-replay-tamper' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const aliceDh = smp.generateX25519KeyPair(filled(32, 173));
  const bobDh = smp.generateX25519KeyPair(filled(32, 174));
  const root = filled(32, 175);
  const senderRatchet = createRatchetState({ rootKey: root, ownDhKey: aliceDh, remoteDhPublicKey: bobDh.publicKey });
  const receiverRatchet = createRatchetState({ rootKey: root, ownDhKey: bobDh, initializeSending: false });
  const queue = {
    rcvId: filled(24, 176),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 177)),
    serverDhSecret: filled(32, 178)
  };
  store.saveContact('alice', { id: 'alice', state: 'active', inboxQueueId: 'alice:inbox' });
  store.saveQueue('alice:inbox', queue);
  store.saveRatchet('alice', receiverRatchet);

  const packet = encryptRatchetMessage(senderRatchet, smp.utf8Bytes('original'), { nonce: filled(24, 179) }).packet;
  const msgId = filled(24, 180);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 779n,
    body: packetBytes(packet)
  });
  const changed = new Uint8Array(body);
  changed[changed.length - 1] ^= 1;
  transport.pushResponse('msg-original', { type: 'MSG', msgId, body }, queue.rcvId);
  transport.pushResponse('ack-original', { type: 'OK' }, queue.rcvId);
  await contacts.receiveNext('alice', { ackCorrId: 'ack-original' });

  transport.pushResponse('msg-changed', { type: 'MSG', msgId, body: changed }, queue.rcvId);
  transport.pushResponse('ack-should-not-send', { type: 'OK' }, queue.rcvId);
  await assert.rejects(() => contacts.receiveNext('alice', { ackCorrId: 'ack-should-not-send' }), /replay/i);
  assert.equal(transport.sent.length, 1);
});

test('contact client rejects malformed payloads before persisting ratchet advance', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-payload-malformed-ratchet' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const aliceDh = smp.generateX25519KeyPair(filled(32, 181));
  const bobDh = smp.generateX25519KeyPair(filled(32, 182));
  const root = filled(32, 183);
  const senderRatchet = createRatchetState({ rootKey: root, ownDhKey: aliceDh, remoteDhPublicKey: bobDh.publicKey });
  const receiverRatchet = createRatchetState({ rootKey: root, ownDhKey: bobDh, initializeSending: false });
  const queue = {
    rcvId: filled(24, 184),
    rcvSignKey: smp.generateEd25519KeyPair(filled(32, 185)),
    serverDhSecret: filled(32, 186)
  };
  store.saveContact('alice', { id: 'alice', state: 'active', inboxQueueId: 'alice:inbox' });
  store.saveQueue('alice:inbox', queue);
  store.saveRatchet('alice', receiverRatchet);

  const malformed = CONTACT_PAYLOAD_PREFIX + '<not-json>';
  const packet = encryptRatchetMessage(senderRatchet, smp.utf8Bytes(malformed), { nonce: filled(24, 187) }).packet;
  const msgId = filled(24, 188);
  const body = encryptRcvMessageBody({
    serverDhSecret: queue.serverDhSecret,
    msgId,
    timestamp: 780n,
    body: packetBytes(packet)
  });
  transport.pushResponse('msg-malformed-payload', { type: 'MSG', msgId, body }, queue.rcvId);
  transport.pushResponse('ack-should-not-send', { type: 'OK' }, queue.rcvId);

  await assert.rejects(() => contacts.receiveNext('alice', { ackCorrId: 'ack-should-not-send' }), /payload JSON/i);

  assert.equal(store.loadRatchet('alice').receiveCount, 0);
  assert.equal(store.list('received').length, 0);
  assert.equal(transport.sent.length, 0);
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
  const firstSend = smp.parseSignedTransmission(4, transport.sent[0].bytes);
  const retrySend = smp.parseSignedTransmission(4, transport.sent[1].bytes);
  assert.equal(smp.equalBytes(firstSend.command.body, retrySend.command.body), true);
});

test('contact client delete scrubs durable queues ratchets and pending retries', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-delete' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const outbox = {
    sndId: filled(24, 80),
    senderSignKey: smp.generateEd25519KeyPair(filled(32, 81))
  };
  store.saveContact('alice', {
    id: 'alice',
    state: 'active',
    inboxQueueId: 'alice:custom-inbox',
    outboxQueueId: 'alice:custom-outbox',
    outboundQueue: outbox,
    remoteProfile: { displayName: 'Bob' },
    invitationUri: 'smp://secret'
  });
  store.saveQueue('alice:custom-inbox', { rcvId: filled(24, 82), rcvSignKey: smp.generateEd25519KeyPair(filled(32, 83)) });
  store.saveQueue('alice:custom-outbox', outbox);
  store.saveQueue('alice:inbox', { rcvId: filled(24, 84) });
  store.saveQueue('alice:outbox', outbox);
  store.saveRatchet('alice', {
    rootKey: filled(32, 85),
    ownDhKey: smp.generateX25519KeyPair(filled(32, 86)),
    remoteDhPublicKey: smp.generateX25519KeyPair(filled(32, 87)).publicKey,
    sendingChainKey: filled(32, 88)
  });
  contacts.scheduler.enqueue('alice:send:secret', { type: 'sendPacket', contactId: 'alice', packet: smp.encodeBase64Url(filled(8, 89)) });
  contacts.scheduler.enqueue('bob:send:keep', { type: 'sendPacket', contactId: 'bob', packet: smp.encodeBase64Url(filled(8, 90)) });
  store.save('received', 'rx:alice', {
    contactId: 'alice',
    msgId: smp.encodeBase64Url(filled(24, 91)),
    bodyHash: smp.encodeBase64Url(filled(32, 92))
  });
  store.save('received', 'rx:bob', {
    contactId: 'bob',
    msgId: smp.encodeBase64Url(filled(24, 93)),
    bodyHash: smp.encodeBase64Url(filled(32, 94))
  });
  for (let i = 0; i < SIMPLEX_STORE_MAX_LIST_ITEMS + 5; i += 1) {
    store.save('received', 'rx:filler-' + String(i).padStart(4, '0'), {
      contactId: 'carol',
      msgId: smp.encodeBase64Url(filled(24, i % 256)),
      bodyHash: smp.encodeBase64Url(filled(32, (i + 1) % 256))
    });
  }
  assert.equal(store.list('received').some((row) => row.id === 'rx:alice'), false);
  store.storage.setItem('simplex-web-v1:contacts-delete:received:corrupt', 'not-json');

  const deleted = contacts.deleteContact('alice');
  assert.equal(deleted.state, 'active');
  const tombstone = store.loadContact('alice');
  assert.equal(tombstone.state, 'deleted');
  assert.equal(tombstone.outboundQueue, undefined);
  assert.equal(tombstone.invitationUri, undefined);
  assert.equal(store.loadQueue('alice:custom-inbox'), null);
  assert.equal(store.loadQueue('alice:custom-outbox'), null);
  assert.equal(store.loadQueue('alice:inbox'), null);
  assert.equal(store.loadQueue('alice:outbox'), null);
  assert.equal(store.loadRatchet('alice'), null);
  assert.deepEqual(store.listPending().map((task) => task.payload.contactId), ['bob']);
  assert.equal(store.load('received', 'rx:alice'), null);
  assert.equal(store.load('received', 'rx:bob').contactId, 'bob');
  assert.equal(store.storage.getItem('simplex-web-v1:contacts-delete:received:corrupt'), null);
});

test('contact client delete everywhere sends remote DEL before local scrub', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-delete-everywhere' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const customInbox = { rcvId: filled(24, 95), rcvSignKey: smp.generateEd25519KeyPair(filled(32, 96)) };
  const fallbackInbox = { rcvId: filled(24, 97), rcvSignKey: smp.generateEd25519KeyPair(filled(32, 98)) };
  store.saveContact('alice', {
    id: 'alice',
    state: 'active',
    inboxQueueId: 'alice:custom-inbox',
    outboxQueueId: 'alice:outbox',
    outboundQueue: { sndId: filled(24, 99), senderSignKey: smp.generateEd25519KeyPair(filled(32, 100)) }
  });
  store.saveQueue('alice:custom-inbox', customInbox);
  store.saveQueue('alice:inbox', fallbackInbox);
  store.saveQueue('alice:outbox', { sndId: filled(24, 101), senderSignKey: smp.generateEd25519KeyPair(filled(32, 102)) });
  store.saveRatchet('alice', {
    rootKey: filled(32, 103),
    ownDhKey: smp.generateX25519KeyPair(filled(32, 104)),
    remoteDhPublicKey: smp.generateX25519KeyPair(filled(32, 105)).publicKey
  });
  transport.pushResponse('del-custom', { type: 'OK' }, customInbox.rcvId);
  transport.pushResponse('del-fallback', { type: 'OK' }, fallbackInbox.rcvId);

  const result = await contacts.deleteContactEverywhere('alice', { corrIds: ['del-custom', 'del-fallback'] });

  assert.deepEqual(result.remoteDeletedQueues, ['alice:custom-inbox', 'alice:inbox']);
  const commands = transport.sent.map((sent) => smp.parseSignedTransmission(4, sent.bytes).command.type);
  assert.deepEqual(commands, ['DEL', 'DEL']);
  const first = smp.parseSignedTransmission(4, transport.sent[0].bytes);
  const second = smp.parseSignedTransmission(4, transport.sent[1].bytes);
  assert.equal(smp.equalBytes(first.queueId, customInbox.rcvId), true);
  assert.equal(smp.equalBytes(second.queueId, fallbackInbox.rcvId), true);
  assert.equal(smp.ed25519Verify(customInbox.rcvSignKey.publicKey, first.signed, first.signature), true);
  assert.equal(smp.ed25519Verify(fallbackInbox.rcvSignKey.publicKey, second.signed, second.signature), true);
  assert.equal(store.loadContact('alice').state, 'deleted');
  assert.equal(store.loadQueue('alice:custom-inbox'), null);
  assert.equal(store.loadQueue('alice:inbox'), null);
  assert.equal(store.loadRatchet('alice'), null);
});

test('contact client delete everywhere preserves local secrets when remote DEL fails', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-delete-everywhere-fail' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const inbox = { rcvId: filled(24, 106), rcvSignKey: smp.generateEd25519KeyPair(filled(32, 107)) };
  store.saveContact('alice', { id: 'alice', state: 'active', inboxQueueId: 'alice:inbox' });
  store.saveQueue('alice:inbox', inbox);
  store.saveRatchet('alice', {
    rootKey: filled(32, 108),
    ownDhKey: smp.generateX25519KeyPair(filled(32, 109)),
    remoteDhPublicKey: smp.generateX25519KeyPair(filled(32, 110)).publicKey
  });

  await assert.rejects(() => contacts.deleteContactEverywhere('alice', { corrId: 'del-missing' }), /no fake responses/);

  assert.equal(store.loadContact('alice').state, 'active');
  assert.equal(store.loadQueue('alice:inbox').rcvId.length, 24);
  assert.equal(store.loadRatchet('alice').rootKey.length, 32);
});

test('contact client delete everywhere falls back from hostile stored inbox ids', async () => {
  const transport = new FakeTransport();
  const client = createBrowserSimplexClient({ transport });
  const store = createBrowserSimplexStore({ namespace: 'contacts-delete-everywhere-hostile' });
  const contacts = createBrowserSimplexContactClient({ client, store });
  const inbox = { rcvId: filled(24, 111), rcvSignKey: smp.generateEd25519KeyPair(filled(32, 112)) };
  store.saveContact('alice', { id: 'alice', state: 'active', inboxQueueId: '../alice' });
  store.saveQueue('alice:inbox', inbox);
  transport.pushResponse('del-fallback', { type: 'OK' }, inbox.rcvId);

  const result = await contacts.deleteContactEverywhere('alice', { corrId: 'del-fallback' });

  assert.deepEqual(result.remoteDeletedQueues, ['alice:inbox']);
  const sent = smp.parseSignedTransmission(4, transport.sent[0].bytes);
  assert.equal(sent.command.type, 'DEL');
  assert.equal(smp.equalBytes(sent.queueId, inbox.rcvId), true);
  assert.equal(store.loadContact('alice').state, 'deleted');
  assert.equal(store.loadQueue('alice:inbox'), null);
});

test('contact payload decoder preserves plain text and rejects malformed prefixed payloads', () => {
  assert.deepEqual(decodeContactPayload('hello'), { type: 'text', text: 'hello' });
  assert.deepEqual(decodeContactPayload(encodeContactPayload({ type: 'text', text: 'hello', messageRef: 'm-1' })).messageRef, 'm-1');
  assert.equal(decodeContactPayload(encodeContactPayload({ type: 'read-receipt', messageRef: 'm-2' })).type, 'read-receipt');
  assert.throws(() => decodeContactPayload(encodeContactPayload({ type: 'read-receipt', messageRef: '../bad' })), /message ref/i);
  assert.throws(() => decodeContactPayload(CONTACT_PAYLOAD_PREFIX + '{"type":"file"}'), /file payload/i);
  assert.throws(() => decodeContactPayload(CONTACT_PAYLOAD_PREFIX + '<script>bad()</script>'), /JSON/i);
});
