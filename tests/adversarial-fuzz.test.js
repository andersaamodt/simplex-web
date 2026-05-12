const test = require('node:test');
const assert = require('node:assert/strict');
const fc = require('fast-check');

const ui = require('../src/default-chat.js');
const sessionStore = require('../src/session-store.js');
const transport = require('../src/transport.js');

const FUZZ_SEED = 0x51a7f00d;

const hostileString = fc.oneof(
  fc.string({ maxLength: 320 }),
  fc.constantFrom(
    '',
    '   ',
    '<script>globalThis.__simplexWebFuzzXss=1</script>',
    '"><img src=x onerror=globalThis.__simplexWebFuzzXss=1>',
    "' autofocus onfocus='globalThis.__simplexWebFuzzXss=1'",
    'javascript:globalThis.__simplexWebFuzzXss=1',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'https://evil.example/tracker.png',
    'http://127.0.0.1:5226/files?path=%2Ftmp%2Fok.png',
    '../outside\nforged=1',
    'emoji 🚧 and null \u0000 and rtl \u202e'
  )
);

function attrValues(html, attrName) {
  const re = new RegExp('\\s' + attrName + '="([^"]*)"', 'g');
  const values = [];
  let match;
  while ((match = re.exec(html))) {
    values.push(match[1]);
  }
  return values;
}

function assertNoExecutableHtml(html) {
  assert.doesNotMatch(html, /<script[\s>]/i);
  for (const tag of html.match(/<[^>]+>/g) || []) {
    const attributeNamesOnly = tag.replace(/"[^"]*"/g, '""').replace(/'[^']*'/g, "''");
    assert.doesNotMatch(attributeNamesOnly, /\son[a-z]+\s*=/i);
  }
  for (const value of attrValues(html, 'href').concat(attrValues(html, 'src'))) {
    assert.doesNotMatch(value, /^javascript:/i);
    assert.doesNotMatch(value, /^data:text\/html/i);
    if (/^https?:\/\//i.test(value)) {
      assert.match(value, /^https?:\/\/(?:127\.0\.0\.1|localhost|\[?::1\]?)(?::|\/|$)/i);
    }
  }
}

test('default chat render is resilient to fuzzed hostile model input', () => {
  const attachmentArb = fc.record({
    name: hostileString,
    mime: hostileString,
    size: fc.oneof(fc.integer({ min: -100000, max: 1000000000 }), hostileString),
    data_url: hostileString,
    url: hostileString
  }, { requiredKeys: [] });
  const messageArb = fc.record({
    direction: hostileString,
    message_kind: hostileString,
    delivery_status: hostileString,
    created_at: hostileString,
    text: hostileString,
    attachment: fc.option(attachmentArb, { nil: undefined })
  }, { requiredKeys: [] });
  const uploadArb = fc.record({
    upload_id: hostileString,
    name: hostileString,
    status: hostileString,
    progress: fc.oneof(fc.integer({ min: -1000, max: 10000 }), hostileString)
  }, { requiredKeys: [] });

  fc.assert(fc.property(
    fc.array(messageArb, { maxLength: ui.MAX_RENDER_MESSAGES + 40 }),
    fc.array(uploadArb, { maxLength: ui.MAX_RENDER_UPLOADS + 20 }),
    hostileString,
    hostileString,
    (messages, uploads, draftText, transportError) => {
      const html = ui.renderPanel({
        loggedIn: true,
        hasSigner: true,
        simplexWebIntroDismissed: true,
        draftText,
        service: {
          transport_status: 'connected',
          transport_error: transportError
        },
        messages,
        uploads
      });

      assertNoExecutableHtml(html);
      assert.ok(html.length < 2000000);
      assert.ok((html.match(/secure-chat-message/g) || []).length <= ui.MAX_RENDER_MESSAGES);
    }
  ), { numRuns: 180, seed: FUZZ_SEED });
});

test('session store fuzzing preserves bounded keys and stored state shape', () => {
  const messageArb = fc.record({
    seq: fc.oneof(fc.integer({ min: -1000, max: 1000000 }), hostileString),
    direction: hostileString,
    message_ref: hostileString,
    message_kind: hostileString,
    delivery_status: hostileString,
    created_at: hostileString,
    updated_at: hostileString,
    text: hostileString,
    attachment: fc.option(fc.record({
      name: hostileString,
      mime: hostileString,
      size: fc.oneof(fc.integer({ min: -1000, max: 1000000 }), hostileString),
      data_url: hostileString,
      url: hostileString
    }, { requiredKeys: [] }), { nil: undefined })
  }, { requiredKeys: [] });
  const uploadArb = fc.record({
    upload_id: hostileString,
    name: hostileString,
    status: hostileString,
    progress: fc.oneof(fc.integer({ min: -1000, max: 10000 }), hostileString),
    error: hostileString
  }, { requiredKeys: [] });

  fc.assert(fc.property(
    hostileString,
    hostileString,
    hostileString,
    fc.array(messageArb, { maxLength: sessionStore.MAX_MESSAGES + 30 }),
    fc.array(uploadArb, { maxLength: sessionStore.MAX_UPLOADS + 20 }),
    (siteKey, accountKey, draftText, messages, uploads) => {
      const backing = new Map();
      const storage = {
        getItem(key) { return backing.get(key) || null; },
        setItem(key, value) { backing.set(key, value); },
        removeItem(key) { backing.delete(key); }
      };
      const saved = sessionStore.writeSession(storage, siteKey, accountKey, {
        draftText,
        messages,
        uploads,
        lastSeq: Number.NaN
      });
      const keys = Array.from(backing.keys());

      assert.equal(keys.length, 1);
      assert.doesNotMatch(keys[0], /[\s/\\]/);
      assert.equal(saved.messages.length <= sessionStore.MAX_MESSAGES, true);
      assert.equal(saved.uploads.length <= sessionStore.MAX_UPLOADS, true);
      assert.equal(saved.draftText.length <= 4000, true);
      assert.deepEqual(sessionStore.readSession(storage, siteKey, accountKey), saved);
    }
  ), { numRuns: 180, seed: FUZZ_SEED + 1 });
});

test('transport normalization fuzzing keeps adapter payloads bounded', () => {
  const payloadArb = fc.record({
    contact_id: hostileString,
    contactId: hostileString,
    contact_link: hostileString,
    contactLink: hostileString,
    owner_contact_link: hostileString,
    text: hostileString,
    client_message_id: hostileString,
    clientMessageId: hostileString,
    message_ref: hostileString,
    user_id: hostileString,
    bridge_user_id: hostileString,
    on_status: fc.constant(() => {})
  }, { requiredKeys: [] });

  fc.assert(fc.property(payloadArb, payloadArb, (payload, options) => {
    const normalized = transport.normalizeOutboundMessage(payload, options);
    assert.equal(normalized.contact_id.length <= transport.MAX_LABEL_LENGTH, true);
    assert.equal(normalized.contact_link.length <= transport.MAX_TEXT_LENGTH, true);
    assert.equal(normalized.text.length <= transport.MAX_TEXT_LENGTH, true);
    assert.equal(normalized.client_message_id.length <= transport.MAX_LABEL_LENGTH, true);
    assert.equal(normalized.message_ref.length <= transport.MAX_LABEL_LENGTH, true);
    assert.equal(normalized.user_id.length <= transport.MAX_LABEL_LENGTH, true);

    const query = transport.normalizeMessageQuery(payload, options);
    assert.equal(Number.isInteger(query.limit), true);
    assert.equal(query.limit >= 1 && query.limit <= 200, true);
  }), { numRuns: 250, seed: FUZZ_SEED + 2 });
});

test('browser simplex client fuzzing rejects hostile correlation ids before transport side effects', async () => {
  const { createBrowserSimplexClient } = await import('../src/browser-simplex-client.mjs');
  const invalidCorrId = hostileString.filter((value) => {
    const raw = String(value == null ? '' : value);
    return raw.length > 32 || /[\u0000-\u001f\u007f-\uffff]/.test(raw);
  });

  await fc.assert(fc.asyncProperty(invalidCorrId, async (corrId) => {
    let sentCount = 0;
    const client = createBrowserSimplexClient({
      transport: {
        async sendSignedTransmissions() {
          sentCount += 1;
        },
        async receiveSignedTransmissions() {
          throw new Error('transport should not receive after invalid input');
        }
      }
    });

    await assert.rejects(
      client.createQueue({ label: 'inbox', corrId }),
      /ASCII|correlation id/
    );
    assert.equal(sentCount, 0);
  }), { numRuns: 120, seed: FUZZ_SEED + 3 });
});

test('browser simplex durable store fuzzing rejects hostile record ids before writes', async () => {
  const { createBrowserSimplexStore } = await import('../src/browser-simplex-store.mjs');
  const invalidId = hostileString.filter((value) => {
    const raw = String(value == null ? '' : value).trim();
    return !raw || raw.length > 160 || /[^A-Za-z0-9_.:-]/.test(raw);
  });

  await fc.assert(fc.asyncProperty(invalidId, async (recordId) => {
    const backing = new Map();
    const storage = {
      getItem(key) { return backing.get(key) || null; },
      setItem(key, value) { backing.set(key, value); },
      removeItem(key) { backing.delete(key); }
    };
    const store = createBrowserSimplexStore({ storage, namespace: 'fuzz' });
    assert.throws(() => store.saveContact(recordId, { state: 'active' }), /record id/);
    assert.equal(backing.size, 0);
  }), { numRuns: 160, seed: FUZZ_SEED + 4 });
});

test('browser XFTP fuzzing round-trips hostile byte payloads and rejects tampering', async () => {
  const { createXftpUpload, assembleXftpDownload } = await import('../src/browser-xftp-core.mjs');
  const { equalBytes } = await import('../src/browser-smp-core.mjs');
  const bytesArb = fc.uint8Array({ maxLength: 4096 });

  await fc.assert(fc.asyncProperty(bytesArb, async (bytes) => {
    const upload = createXftpUpload(bytes, {
      rootKey: new Uint8Array(32).fill(19),
      fileId: 'fuzz-file',
      name: '../fuzz.bin',
      chunkSize: 1024
    });
    assert.equal(equalBytes(assembleXftpDownload(upload.manifest, upload.chunks, upload.rootKey), bytes), true);

    const tampered = upload.chunks.map((chunk, index) => index === 0
      ? { ...chunk, ciphertext: new Uint8Array(chunk.ciphertext) }
      : chunk);
    tampered[0].ciphertext[0] ^= 1;
    assert.throws(() => assembleXftpDownload(upload.manifest, tampered, upload.rootKey), /decryption failed|hash/i);
  }), { numRuns: 120, seed: FUZZ_SEED + 5 });
});

test('browser SMP server profile fuzzing rejects unsafe production downgrades', async () => {
  const { assertProductionBrowserSmpServerProfile } = await import('../src/browser-smp-server-profile.mjs');
  const { encodeBase64Url } = await import('../src/browser-smp-core.mjs');
  const unsafeUrl = hostileString.filter((value) => !/^https:\/\/|^wss:\/\//i.test(String(value == null ? '' : value).trim()));

  await fc.assert(fc.asyncProperty(unsafeUrl, async (url) => {
    assert.throws(() => assertProductionBrowserSmpServerProfile({
      version: 1,
      transport: 'websocket',
      url,
      allowedOrigins: ['https://app.example.test'],
      keyHash: encodeBase64Url(new Uint8Array(32).fill(2)),
      sessionBinding: { type: 'signed-handshake' }
    }), /URL|wss|https|invalid/i);
  }), { numRuns: 120, seed: FUZZ_SEED + 6 });
});
