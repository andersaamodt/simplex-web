import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium, firefox, webkit } from '@playwright/test';

const repoRoot = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const defaultChatJs = pathToFileURL(join(repoRoot, 'src/default-chat.js')).href;
const defaultChatCss = pathToFileURL(join(repoRoot, 'src/default-chat.css')).href;
const tinyPng = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=';
const playwrightCache = join(process.env.HOME || '', 'Library/Caches/ms-playwright');

function firstExisting(paths) {
  return paths.find((candidate) => candidate && existsSync(candidate)) || '';
}

async function writeProbePage() {
  const dir = await mkdtemp(join(tmpdir(), 'simplex-web-browser-matrix-'));
  const file = join(dir, 'probe.html');
  await writeFile(file, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>simplex-web browser matrix probe</title>
  <link rel="stylesheet" href="${defaultChatCss}">
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; font: 15px system-ui, sans-serif; background: #f7f8fb; color: #172026; }
    main { width: min(740px, calc(100vw - 24px)); margin: 12px auto; }
    #probe-status { display: inline-flex; margin-bottom: 10px; padding: 5px 8px; border: 1px solid #a8d8b4; border-radius: 6px; background: #eef8f0; color: #174325; }
  </style>
</head>
<body>
  <main>
    <div id="probe-status">loading</div>
    <div id="secure-chat-root"></div>
  </main>
  <script src="${defaultChatJs}"></script>
  <script>
    window.__simplexWebBrowserMatrixXss = 0;
    const longHostile = 'quoted " attachment <img src=x onerror=window.__simplexWebBrowserMatrixXss=1> '.repeat(5);
    window.SimplexWebDefaultChat.mount(document.getElementById('secure-chat-root'), {
      loggedIn: true,
      hasSigner: true,
      simplexWebIntroDismissed: true,
      draftText: '</textarea><script>window.__simplexWebBrowserMatrixXss=1</scr' + 'ipt>',
      pendingFiles: [{ id: 'pending-1', name: longHostile, mime: 'image/png', size: 2048 }],
      messages: [
        {
          direction: 'incoming',
          text: '<script>window.__simplexWebBrowserMatrixXss=1</scr' + 'ipt>',
          delivery_status: 'received',
          created_at: '2026-05-11T00:00:00Z',
          attachment: { name: longHostile, mime: 'image/png', size: 67, data_url: '${tinyPng}' }
        },
        {
          direction: 'outgoing',
          text: 'remote URL should not autoload',
          delivery_status: 'sending',
          created_at: '2026-05-11T00:01:00Z',
          attachment: { name: 'remote.png', mime: 'image/png', size: 12, url: 'https://evil.example/tracker.png' }
        }
      ]
    }, {});
    requestAnimationFrame(() => {
      const remoteAutoload = !!document.querySelector('img[src^="https://evil.example"], video[src^="https://evil.example"], audio[src^="https://evil.example"]');
      const fitsViewport = document.documentElement.scrollWidth <= window.innerWidth + 1;
      document.getElementById('probe-status').textContent =
        !remoteAutoload && fitsViewport && window.__simplexWebBrowserMatrixXss === 0 ? 'passed' : 'failed';
    });
  </script>
</body>
</html>`);
  return { dir, url: pathToFileURL(file).href };
}

const browsers = [
  ['chromium', chromium, process.env.SIMPLEX_WEB_CHROMIUM_EXECUTABLE || firstExisting([
    join(playwrightCache, 'chromium-1208/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'),
    join(playwrightCache, 'chromium-1187/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing')
  ])],
  ['firefox', firefox, process.env.SIMPLEX_WEB_FIREFOX_EXECUTABLE || firstExisting([
    join(playwrightCache, 'firefox-1509/firefox/Nightly.app/Contents/MacOS/firefox'),
    '/Applications/Firefox.app/Contents/MacOS/firefox'
  ])],
  ['webkit', webkit, process.env.SIMPLEX_WEB_WEBKIT_EXECUTABLE || '']
];

for (const [name, browserType, executablePath] of browsers) {
  test(`browser matrix renders securely in ${name}`, { timeout: 120000 }, async (t) => {
    const probe = await writeProbePage();
    let browser;
    try {
      browser = await browserType.launch({
        headless: true,
        ...(executablePath ? { executablePath } : {})
      });
    } catch (error) {
      await rm(probe.dir, { recursive: true, force: true });
      if (/Executable doesn't exist|executable doesn't exist|not found|ENOENT/i.test(error && error.message || '')) {
        t.skip(`${name} executable is unavailable in this desktop environment`);
        return;
      }
      throw error;
    }
    try {
      for (const viewport of [
        { width: 390, height: 844 },
        { width: 1024, height: 768 }
      ]) {
        const page = await browser.newPage({ viewport });
        await page.goto(probe.url);
        await page.waitForFunction(() => document.getElementById('probe-status')?.textContent !== 'loading');
        const result = await page.evaluate(() => ({
          status: document.getElementById('probe-status').textContent,
          xss: window.__simplexWebBrowserMatrixXss,
          remoteAutoloads: document.querySelectorAll('img[src^="https://evil.example"], video[src^="https://evil.example"], audio[src^="https://evil.example"]').length,
          panel: !!document.querySelector('.secure-chat-panel'),
          scrollWidth: document.documentElement.scrollWidth,
          innerWidth: window.innerWidth
        }));

        assert.equal(result.status, 'passed');
        assert.equal(result.xss, 0);
        assert.equal(result.remoteAutoloads, 0);
        assert.equal(result.panel, true);
        assert.equal(result.scrollWidth <= result.innerWidth + 1, true);
        await page.close();
      }
    } finally {
      await browser.close();
      await rm(probe.dir, { recursive: true, force: true });
    }
  });
}
