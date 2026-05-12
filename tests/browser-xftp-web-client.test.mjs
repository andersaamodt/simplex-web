import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

import {
  asciiBytes,
  concatBytes,
  decodePublicKeyDer,
  ed25519Sign,
  encodeLargeBytes,
  encodePublicKeyDer,
  encodeSmallBytes,
  equalBytes,
  generateEd25519KeyPair,
  generateX25519KeyPair,
  padBlock,
  sha256Hash,
  unpadBlock,
  x25519SharedSecret
} from '../src/browser-smp-core.mjs';
import {
  XFTP_WEB_BLOCK_SIZE,
  connectBrowserXftpWebClient,
  createXftpWebFile,
  decodeXftpWebResponse,
  decodeXftpWebTransmission,
  decodeXftpWebServerHandshake,
  decryptXftpWebTransportChunk,
  deleteXftpWebFile,
  downloadXftpWebFileChunk,
  encodeXftpWebClientHandshake,
  encodeXftpWebClientHello,
  encodeXftpWebFNEW,
  encodeXftpWebFPUT,
  encodeXftpWebPING,
  encodeXftpWebSignedKeyForTests,
  encodeXftpWebTransmission,
  encryptXftpWebTransportChunk,
  getXftpWebFile,
  normalizeXftpWebUrl,
  parseXftpWebServerAddress,
  pingXftpWeb,
  putXftpWebFile,
  verifyXftpWebIdentityProof
} from '../src/browser-xftp-web-client.mjs';

function filled(length, value) {
  return new Uint8Array(length).fill(value);
}

function derLength(length) {
  if (length < 0x80) return new Uint8Array([length]);
  var bytes = [];
  var n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function der(tag, body) {
  return concatBytes(new Uint8Array([tag]), derLength(body.length), body);
}

function derSequence(...parts) {
  return der(0x30, concatBytes(...parts));
}

function derInteger(value) {
  return der(0x02, new Uint8Array([value & 0xff]));
}

function derBitString(bytes) {
  return der(0x03, concatBytes(new Uint8Array([0]), bytes));
}

function ed25519Algorithm() {
  return derSequence(new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x70]));
}

function fakeCertificate(publicKeyDer) {
  var tbs = derSequence(
    derInteger(1),
    ed25519Algorithm(),
    derSequence(),
    derSequence(),
    derSequence(),
    publicKeyDer
  );
  return derSequence(tbs, ed25519Algorithm(), derBitString(filled(64, 9)));
}

function decodeClientHello(block) {
  var body = unpadBlock(block, XFTP_WEB_BLOCK_SIZE);
  assert.equal(body[0], 0x31);
  assert.equal(body[1], 32);
  return body.slice(2, 34);
}

function makeHandshake(challenge, options = {}) {
  var leaf = options.leaf || generateEd25519KeyPair(filled(32, 41));
  var leafCert = fakeCertificate(leaf.publicKeyDer);
  var idCert = fakeCertificate(generateEd25519KeyPair(filled(32, 42)).publicKeyDer);
  var keyHash = sha256Hash(idCert);
  var sessionId = options.sessionId || filled(32, 43);
  var serverDh = generateX25519KeyPair(filled(32, 44));
  var signedKeyDer = encodeXftpWebSignedKeyForTests(serverDh.publicKeyDer, leaf.secretKey);
  var proof = options.omitProof ? new Uint8Array() : ed25519Sign(leaf.secretKey, concatBytes(challenge, sessionId));
  var body = concatBytes(
    new Uint8Array([0, 1, 0, 3]),
    encodeSmallBytes(sessionId),
    new Uint8Array([2]),
    encodeLargeBytes(leafCert),
    encodeLargeBytes(idCert),
    encodeLargeBytes(signedKeyDer),
    encodeSmallBytes(proof)
  );
  return {
    block: padBlock(body, XFTP_WEB_BLOCK_SIZE),
    keyHash,
    sessionId,
    leaf,
    leafCert,
    idCert,
    signedKeyDer,
    proof
  };
}

async function readBody(request) {
  var chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return new Uint8Array(Buffer.concat(chunks));
}

async function withLoopbackXftpWebServer(fn, options = {}) {
  var transcript = [];
  var storedBody = null;
  var serverDh = generateX25519KeyPair(filled(32, 52));
  var server = http.createServer(async (request, response) => {
    try {
      var body = await readBody(request);
      if (request.headers['xftp-web-hello']) {
        var challenge = decodeClientHello(body);
        var hs = makeHandshake(challenge, { omitProof: options.omitProof });
        transcript.push({ type: 'hello', challenge, handshake: hs });
        response.writeHead(200, { 'content-type': 'application/octet-stream' });
        response.end(Buffer.from(hs.block));
        return;
      }
      var latest = transcript.find((row) => row.type === 'hello').handshake;
      if (request.headers['xftp-handshake']) {
        var clientHs = unpadBlock(body, XFTP_WEB_BLOCK_SIZE);
        assert.equal(clientHs[0], 0);
        assert.equal(clientHs[1], 3);
        assert.equal(equalBytes(clientHs.slice(3, 35), latest.keyHash), true);
        transcript.push({ type: 'handshake' });
        response.writeHead(200, { 'content-type': 'application/octet-stream' });
        response.end(Buffer.alloc(0));
        return;
      }
      var block = body.slice(0, XFTP_WEB_BLOCK_SIZE);
      var chunk = body.slice(XFTP_WEB_BLOCK_SIZE);
      var tx = decodeXftpWebTransmission(latest.sessionId, block);
      var command = String.fromCharCode(...tx.commandBytes.slice(0, 4));
      transcript.push({ type: 'command', command, tx, chunk });
      var responseCommand;
      var responseBody = new Uint8Array();
      if (command === 'PING') {
        responseCommand = asciiBytes('PONG');
      } else if (command === 'FNEW') {
        responseCommand = concatBytes(asciiBytes('SIDS '), encodeSmallBytes(filled(6, 61)), new Uint8Array([1]), encodeSmallBytes(filled(6, 62)));
      } else if (command === 'FPUT') {
        storedBody = chunk;
        responseCommand = asciiBytes('OK');
      } else if (command === 'FGET') {
        var dhKeyDer = tx.commandBytes.slice(6, 6 + tx.commandBytes[5]);
        var requestDh = decodePublicKeyDer(dhKeyDer);
        var nonce = filled(24, 63);
        var dhSecret = x25519SharedSecret(serverDh.secretKey, requestDh.rawPublicKey);
        responseCommand = concatBytes(asciiBytes('FILE '), encodeSmallBytes(encodePublicKeyDer('X25519', serverDh.publicKey)), nonce);
        responseBody = encryptXftpWebTransportChunk(dhSecret, nonce, storedBody || filled(4, 64));
      } else if (command === 'FDEL') {
        storedBody = null;
        responseCommand = asciiBytes('OK');
      } else {
        responseCommand = asciiBytes('ERR CMD UNKNOWN');
      }
      response.writeHead(200, { 'content-type': 'application/octet-stream' });
      response.end(Buffer.from(concatBytes(
        encodeXftpWebTransmission({ sessionId: latest.sessionId, commandBytes: responseCommand }),
        responseBody
      )));
    } catch (error) {
      response.writeHead(500, { 'content-type': 'text/plain' });
      response.end(error && error.stack || String(error));
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    await fn({
      url: `http://127.0.0.1:${server.address().port}/`,
      transcript
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('XFTP web protocol encodes padded hello handshake commands and broker responses', () => {
  var challenge = filled(32, 1);
  var helloBody = unpadBlock(encodeXftpWebClientHello({ webChallenge: challenge }), XFTP_WEB_BLOCK_SIZE);
  assert.equal(helloBody[0], 0x31);
  assert.equal(helloBody[1], 32);
  assert.equal(equalBytes(helloBody.slice(2), challenge), true);

  var handshakeBody = unpadBlock(encodeXftpWebClientHandshake({
    version: 3,
    keyHash: filled(32, 2)
  }), XFTP_WEB_BLOCK_SIZE);
  assert.deepEqual(Array.from(handshakeBody.slice(0, 3)), [0, 3, 32]);
  assert.equal(equalBytes(handshakeBody.slice(3), filled(32, 2)), true);

  var sessionId = filled(32, 3);
  var decoded = decodeXftpWebTransmission(sessionId, encodeXftpWebTransmission({
    sessionId,
    commandBytes: encodeXftpWebPING()
  }));
  assert.equal(String.fromCharCode(...decoded.commandBytes), 'PING');
  assert.equal(decodeXftpWebResponse(asciiBytes('PONG')).type, 'PONG');
  assert.equal(String.fromCharCode(...encodeXftpWebFPUT()), 'FPUT');
  assert.equal(String.fromCharCode(...encodeXftpWebFNEW({
    sndKey: encodePublicKeyDer('Ed25519', filled(32, 4)),
    size: 5,
    digest: filled(32, 6)
  }, [encodePublicKeyDer('Ed25519', filled(32, 7))]).slice(0, 4)), 'FNEW');
});

test('XFTP web server identity proof verifies key hash challenge and signed key', () => {
  var challenge = filled(32, 11);
  var built = makeHandshake(challenge);
  var handshake = decodeXftpWebServerHandshake(built.block);
  assert.equal(verifyXftpWebIdentityProof({
    handshake,
    challenge,
    keyHash: built.keyHash
  }), true);
  assert.equal(verifyXftpWebIdentityProof({
    handshake,
    challenge: filled(32, 12),
    keyHash: built.keyHash
  }), false);
  assert.equal(verifyXftpWebIdentityProof({
    handshake,
    challenge,
    keyHash: filled(32, 13)
  }), false);
});

test('XFTP web URL and address parsing reject plaintext remote and path smuggling', () => {
  var keyHash = makeHandshake(filled(32, 21)).keyHash;
  var address = 'xftp://' + Buffer.from(keyHash).toString('base64url') + '@xftp.example.test:443';
  assert.equal(parseXftpWebServerAddress(address).host, 'xftp.example.test');
  assert.throws(() => parseXftpWebServerAddress(address + '/extra'), /address/i);
  assert.throws(() => normalizeXftpWebUrl('http://xftp.example.test/'), /https/i);
  assert.equal(normalizeXftpWebUrl('http://127.0.0.1:8080/', { allowInsecureLocal: true }), 'http://127.0.0.1:8080/');
});

test('XFTP web transport chunk decrypts with digest checks and rejects tampering', () => {
  var dhSecret = filled(32, 31);
  var nonce = filled(24, 32);
  var plaintext = filled(96, 33);
  var encrypted = encryptXftpWebTransportChunk(dhSecret, nonce, plaintext);
  assert.equal(equalBytes(decryptXftpWebTransportChunk(dhSecret, nonce, encrypted, sha256Hash(plaintext)), plaintext), true);
  var tampered = encrypted.slice();
  tampered[4] ^= 1;
  assert.throws(() => decryptXftpWebTransportChunk(dhSecret, nonce, tampered, sha256Hash(plaintext)), /decryption failed/i);
  assert.throws(() => decryptXftpWebTransportChunk(dhSecret, nonce, encrypted, filled(32, 34)), /digest mismatch/i);
});

test('XFTP web client rejects missing server identity proof unless explicit loopback test mode is enabled', async () => {
  await withLoopbackXftpWebServer(async ({ url, transcript }) => {
    var expected = makeHandshake(filled(32, 90)).keyHash;
    await assert.rejects(() => connectBrowserXftpWebClient({
      url,
      keyHash: expected,
      allowInsecureLocal: true,
      timeoutMs: 2000
    }), /identity proof/i);
  }, { omitProof: true });

  await withLoopbackXftpWebServer(async ({ url, transcript }) => {
    var expected = makeHandshake(filled(32, 90)).keyHash;
    var client = await connectBrowserXftpWebClient({
      url,
      keyHash: expected,
      allowInsecureLocal: true,
      allowUnverifiedIdentityForTests: true,
      timeoutMs: 2000
    });
    assert.equal(client.security.unverifiedLoopbackTestMode, true);
  }, { omitProof: true });
});

test('XFTP web client handshakes pings and sends authenticated file commands over fetch', async () => {
  await withLoopbackXftpWebServer(async ({ url, transcript }) => {
    var bootstrap = makeHandshake(filled(32, 91));
    var client = await connectBrowserXftpWebClient({
      url,
      keyHash: bootstrap.keyHash,
      allowInsecureLocal: true,
      allowUnverifiedIdentityForTests: true,
      timeoutMs: 2000
    });
    // The server builds its key hash from the real client challenge, so use the
    // captured value for all command assertions after connection.
    assert.equal(equalBytes(client.keyHash, bootstrap.keyHash), true);
    assert.equal(client.profile, 'simplex-xftp-web-browser-v1');
    assert.equal(client.security.plaintextBridge, false);

    await pingXftpWeb(client);
    var sender = generateEd25519KeyPair(filled(32, 71));
    var recipient = generateEd25519KeyPair(filled(32, 72));
    var created = await createXftpWebFile(client, {
      privateKey: sender.secretKey,
      fileInfo: {
        sndKey: sender.publicKeyDer,
        size: 4,
        digest: filled(32, 73)
      },
      recipientKeys: [recipient.publicKeyDer]
    });
    assert.equal(equalBytes(created.senderId, filled(6, 61)), true);
    assert.equal(equalBytes(created.recipientIds[0], filled(6, 62)), true);

    await putXftpWebFile(client, {
      privateKey: sender.secretKey,
      senderId: created.senderId,
      body: filled(4, 74)
    });
    var downloaded = await getXftpWebFile(client, {
      privateKey: recipient.secretKey,
      recipientId: created.recipientIds[0],
      dhSeed: filled(32, 75)
    });
    assert.equal(downloaded.dhSecret.length, 32);
    assert.equal(equalBytes(decryptXftpWebTransportChunk(downloaded.dhSecret, downloaded.nonce, downloaded.body, sha256Hash(filled(4, 74))), filled(4, 74)), true);
    var downloadedChunk = await downloadXftpWebFileChunk(client, {
      privateKey: recipient.secretKey,
      recipientId: created.recipientIds[0],
      dhSeed: filled(32, 76),
      digest: sha256Hash(filled(4, 74))
    });
    assert.equal(equalBytes(downloadedChunk.plaintext, filled(4, 74)), true);
    await deleteXftpWebFile(client, {
      privateKey: sender.secretKey,
      senderId: created.senderId
    });

    assert.deepEqual(transcript.filter((row) => row.type === 'command').map((row) => row.command), [
      'PING',
      'FNEW',
      'FPUT',
      'FGET',
      'FGET',
      'FDEL'
    ]);
    assert.equal(transcript.some((row) => row.command === 'FPUT' && equalBytes(row.chunk, filled(4, 74))), true);
  });
});
