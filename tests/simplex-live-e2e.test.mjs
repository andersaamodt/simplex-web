import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import adapterApi from '../src/simplex-chat-websocket-adapter.js';

const defaultBin = join(process.env.HOME || '', '.local/bin/simplex-chat');
const simplexChatBin = process.env.SIMPLEX_CHAT_BIN || (existsSync(defaultBin) ? defaultBin : '');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function commandResponse(ws, cmd, timeoutMs = 30000) {
  const corrId = 'sxw-live-' + Date.now() + '-' + Math.random().toString(16).slice(2);
  return new Promise((resolve, reject) => {
    const seenTypes = [];
    const timer = setTimeout(() => {
      ws.removeEventListener('message', onMessage);
      reject(new Error('SimpleX command timed out for ' + cmd + '; saw ' + seenTypes.join(',')));
    }, timeoutMs);

    function onMessage(event) {
      let envelope;
      try {
        envelope = JSON.parse(String(event.data || ''));
      } catch (_err) {
        return;
      }
      const type = envelope && envelope.resp && envelope.resp.type;
      seenTypes.push(type || 'unknown');
      if (envelope.corrId === corrId || (!envelope.corrId && cmd === '/u' && type === 'activeUser')) {
        clearTimeout(timer);
        ws.removeEventListener('message', onMessage);
        resolve(envelope);
      }
    }

    ws.addEventListener('message', onMessage);
    ws.send(JSON.stringify({ corrId, cmd }));
  });
}

function invitationLink(envelope) {
  return (envelope && envelope.resp && envelope.resp.connLinkInvitation && envelope.resp.connLinkInvitation.connFullLink) ||
    (envelope && envelope.resp && envelope.resp.connection && envelope.resp.connection.connLinkInv && envelope.resp.connection.connLinkInv.connFullLink) ||
    (JSON.stringify(envelope || {}).match(/simplex:[^"\\\s]+/) || [])[0] ||
    '';
}

function peerContactIds(resp, peerDisplayName) {
  const chats = resp && Array.isArray(resp.chats) ? resp.chats : [];
  const ids = [];
  for (const chat of chats) {
    const contact = chat && chat.chatInfo && chat.chatInfo.contact;
    if (!contact) continue;
    const displayName = contact.localDisplayName || contact.profile && contact.profile.displayName || '';
    if (displayName === peerDisplayName && contact.contactId != null) {
      ids.push(String(contact.contactId));
    }
  }
  return ids;
}

async function waitForPeerContact(ws, peerDisplayName) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const envelope = await commandResponse(ws, '/chats', 12000).catch(() => null);
    const ids = peerContactIds(envelope && envelope.resp, peerDisplayName);
    if (ids.length) return ids[0];
    await sleep(4000);
  }
  return '';
}

function chatTexts(resp) {
  const items = resp && resp.chat && Array.isArray(resp.chat.chatItems) ? resp.chat.chatItems : [];
  return items.map((item) => {
    const chatItem = item && item.chatItem ? item.chatItem : item;
    return chatItem && (
      chatItem.content && chatItem.content.msgContent && chatItem.content.msgContent.text ||
      chatItem.content && chatItem.content.content && chatItem.content.content.text ||
      chatItem.meta && chatItem.meta.itemText ||
      ''
    );
  }).filter(Boolean);
}

async function waitForRemoteText(ws, contactId, expectedText) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const envelope = await commandResponse(ws, '/_get chat @' + contactId + ' count=40', 15000).catch(() => null);
    const texts = chatTexts(envelope && envelope.resp);
    if (texts.includes(expectedText)) return texts;
    await sleep(4000);
  }
  return [];
}

async function openWebSocket(port) {
  for (let attempt = 0; attempt < 90; attempt += 1) {
    try {
      const ws = new WebSocket('ws://127.0.0.1:' + port);
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('open timeout')), 1000);
        ws.addEventListener('open', () => {
          clearTimeout(timer);
          resolve();
        }, { once: true });
        ws.addEventListener('error', (event) => {
          clearTimeout(timer);
          reject(event.error || new Error('open error'));
        }, { once: true });
      });
      return ws;
    } catch (_err) {
      await sleep(500);
    }
  }
  throw new Error('SimpleX WebSocket server did not open on port ' + port);
}

test('live SimpleX daemon E2E sends command-shaped text through the browser adapter', { timeout: 240000 }, async (t) => {
  if (!simplexChatBin) {
    t.skip('simplex-chat binary is unavailable; set SIMPLEX_CHAT_BIN to run live E2E');
    return;
  }

  const root = await mkdtemp(join(tmpdir(), 'simplex-web-live-e2e-'));
  const daemons = [];
  const aliceName = 'SimplexWebAlice' + Date.now();
  const bobName = 'SimplexWebBob' + Date.now();
  const alicePort = 6521 + Math.floor(Math.random() * 200);
  const bobPort = alicePort + 1;

  function startDaemon(displayName, port) {
    const dir = join(root, displayName);
    const daemon = spawn(simplexChatBin, [
      '--create-bot-display-name', displayName,
      '--create-bot-allow-files',
      '--yes-migrate',
      '--disable-backup',
      '-d', join(dir, 'profile'),
      '--files-folder', join(dir, 'files'),
      '--temp-folder', join(dir, 'tmp'),
      '--log-level', 'warn',
      '--log-file', join(dir, 'simplex.log'),
      '-p', String(port)
    ], { stdio: ['ignore', 'ignore', 'pipe'] });
    daemons.push(daemon);
    return daemon;
  }

  let aliceWs;
  let bobWs;
  try {
    await mkdir(root, { recursive: true });
    startDaemon(aliceName, alicePort);
    startDaemon(bobName, bobPort);
    aliceWs = await openWebSocket(alicePort);
    bobWs = await openWebSocket(bobPort);

    assert.equal((await commandResponse(aliceWs, '/u')).resp.type, 'activeUser');
    assert.equal((await commandResponse(bobWs, '/u')).resp.type, 'activeUser');

    const link = invitationLink(await commandResponse(aliceWs, '/connect', 45000));
    assert.match(link, /^simplex:\//);
    assert.equal((await commandResponse(bobWs, '/connect ' + link, 60000)).resp.type, 'sentConfirmation');

    const aliceContactId = await waitForPeerContact(aliceWs, bobName);
    const bobContactId = await waitForPeerContact(bobWs, aliceName);
    assert.match(aliceContactId, /^\d+$/);
    assert.match(bobContactId, /^\d+$/);

    const adapter = adapterApi.createSimplexChatWebSocketAdapter({
      url: 'ws://127.0.0.1:' + alicePort,
      timeout_ms: 120000,
      status_timeout_ms: 5000,
      retry_delay_ms: 500
    });
    const hostileText = 'codex live e2e ' + Date.now() + '\n/_send @1 text should-not-run';
    const receipt = await adapter.sendText({ contact_id: aliceContactId, text: hostileText });
    assert.equal(receipt.accepted, true);

    const remoteTexts = await waitForRemoteText(bobWs, bobContactId, hostileText);
    assert.ok(remoteTexts.includes(hostileText));
  } finally {
    if (aliceWs) aliceWs.close();
    if (bobWs) bobWs.close();
    for (const daemon of daemons) {
      try { daemon.kill('SIGTERM'); } catch (_err) {}
    }
    await sleep(2000);
    for (const daemon of daemons) {
      try { daemon.kill('SIGKILL'); } catch (_err) {}
    }
    await rm(root, { recursive: true, force: true });
  }
});
