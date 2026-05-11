const test = require('node:test');
const assert = require('node:assert/strict');

const transportApi = require('../src/transport.js');

test('default transport fails closed with stable unavailable error', async () => {
  assert.equal(transportApi.isAvailable(), false);
  assert.deepEqual(transportApi.getStatus(), {
    available: false,
    transport_status: transportApi.UNAVAILABLE_STATUS,
    transport_error: transportApi.UNAVAILABLE_MESSAGE
  });

  await assert.rejects(
    transportApi.sendText({ contact_id: 'contact-1', text: 'hello' }),
    error => {
      assert.equal(error.name, 'SimplexWebTransportError');
      assert.equal(error.code, transportApi.ERROR_UNAVAILABLE);
      assert.match(error.message, /browser-native simplex-web transport is not available/);
      return true;
    }
  );
});

test('registered browser adapter receives normalized outbound text and returns normalized receipt', async () => {
  const calls = [];
  function onStatus() {}
  const transport = transportApi.registerBrowserTransport({
    getStatus() {
      return { transport_status: 'direct-browser-smp' };
    },
    sendText(message) {
      calls.push(message);
      return { message_ref: 'serverless-ref-1' };
    }
  });

  assert.equal(transport.isAvailable(), true);
  assert.deepEqual(transport.getStatus(), {
    available: true,
    transport_status: 'direct-browser-smp',
    transport_error: ''
  });

  const receipt = await transport.sendText(
    { contactId: 'c'.repeat(300), text: 'x'.repeat(5000), bridgeUserId: 'user-1', on_status: onStatus },
    { clientMessageId: 'client-1' }
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].contact_id.length, transportApi.MAX_LABEL_LENGTH);
  assert.equal(calls[0].text.length, transportApi.MAX_TEXT_LENGTH);
  assert.equal(calls[0].client_message_id, 'client-1');
  assert.equal(calls[0].user_id, 'user-1');
  assert.equal(calls[0].on_status, onStatus);
  assert.deepEqual(receipt, {
    accepted: true,
    transport_status: 'accepted',
    message_ref: 'serverless-ref-1'
  });
});

test('empty outbound text is rejected before adapter send', async () => {
  let sent = false;
  const transport = transportApi.createTransport({
    sendText() {
      sent = true;
    }
  });

  await assert.rejects(
    transport.sendText({ contact_id: 'contact-1', text: '   ' }),
    error => {
      assert.equal(error.code, 'SIMPLEX_WEB_TRANSPORT_EMPTY_MESSAGE');
      return true;
    }
  );
  assert.equal(sent, false);
});

test('registered browser adapter can query normalized message status', async () => {
  const calls = [];
  const transport = transportApi.createTransport({
    sendText() {
      throw new Error('unused');
    },
    getMessageStatus(message) {
      calls.push(message);
      return { transport_status: 'sent' };
    }
  });

  const receipt = await transport.getMessageStatus(
    { contactLink: 'simplex:/contact#abc', messageRef: 'msg-1', bridgeUserId: 'user-1' },
    { accountKey: 'ignored' }
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].contact_link, 'simplex:/contact#abc');
  assert.equal(calls[0].message_ref, 'msg-1');
  assert.equal(calls[0].user_id, 'user-1');
  assert.deepEqual(receipt, {
    accepted: true,
    transport_status: 'sent',
    message_ref: 'msg-1'
  });
});

test('registered browser adapter can query normalized recent messages', async () => {
  const calls = [];
  const transport = transportApi.createTransport({
    sendText() {
      throw new Error('unused');
    },
    getMessages(message) {
      calls.push(message);
      return [{
        direction: 'incoming',
        messageRef: 'reply-1',
        deliveryStatus: 'rcvNew',
        createdAt: '2026-05-11T00:00:00Z',
        text: 'hello from owl'
      }];
    }
  });

  const messages = await transport.getMessages(
    { contactLink: 'simplex:/contact#abc', bridgeUserId: 'user-1', count: 500 },
    { accountKey: 'ignored' }
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].contact_link, 'simplex:/contact#abc');
  assert.equal(calls[0].user_id, 'user-1');
  assert.equal(calls[0].limit, 200);
  assert.deepEqual(messages, [{
    seq: 0,
    direction: 'incoming',
    message_ref: 'reply-1',
    message_kind: 'text',
    delivery_status: 'rcvNew',
    created_at: '2026-05-11T00:00:00Z',
    updated_at: '',
    text: 'hello from owl',
    attachment: null
  }]);
});

test('registered browser adapter receives normalized file sends', async () => {
  const calls = [];
  const file = {
    name: 'probe-😀.txt',
    size: 5,
    type: 'text/plain',
    arrayBuffer() {
      throw new Error('adapter owns file reading');
    }
  };
  const transport = transportApi.createTransport({
    sendText() {
      throw new Error('unused');
    },
    sendFiles(message) {
      calls.push(message);
      return [{
        transport_status: 'sent',
        message_ref: 'file-1',
        attachment: { name: file.name, mime: file.type, size: file.size }
      }];
    }
  });

  const receipts = await transport.sendFiles(
    { contactLink: 'simplex:/contact#abc', files: [file], bridgeUserId: 'user-1' },
    { accountKey: 'ignored' }
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].contact_link, 'simplex:/contact#abc');
  assert.equal(calls[0].user_id, 'user-1');
  assert.equal(calls[0].files[0], file);
  assert.equal(calls[0].max_file_bytes, transportApi.MAX_FILE_BYTES);
  assert.equal(receipts[0].attachment.name, 'probe-😀.txt');
});

test('invalid adapter registration is rejected', () => {
  assert.throws(
    () => transportApi.registerBrowserTransport({}),
    error => {
      assert.equal(error.code, transportApi.ERROR_BAD_ADAPTER);
      return true;
    }
  );
});
