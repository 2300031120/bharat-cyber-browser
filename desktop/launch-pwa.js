import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const port = Number(process.env.PORT || 4173);
const home = `http://127.0.0.1:${port}`;
const server = spawn(process.execPath, ['server.js'], {
  cwd: root,
  env: { ...process.env, PORT: String(port) },
  stdio: 'inherit',
  windowsHide: true
});
let browser;

function browserCandidates() {
  if (process.env.BROWSER_BIN) return [process.env.BROWSER_BIN];
  if (process.platform === 'win32') {
    const roots = [process.env['PROGRAMFILES(X86)'], process.env.ProgramFiles, process.env.LOCALAPPDATA].filter(Boolean);
    return roots.flatMap((base) => [
      path.join(base, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(base, 'Google', 'Chrome', 'Application', 'chrome.exe')
    ]);
  }
  if (process.platform === 'darwin') return [
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  ];
  return ['microsoft-edge', 'microsoft-edge-stable', 'google-chrome', 'google-chrome-stable', 'chromium'];
}

function stop() {
  if (browser && browser.exitCode === null) browser.kill();
  if (server && server.exitCode === null) server.kill();
}

process.on('SIGINT', () => { stop(); process.exit(0); });
process.on('SIGTERM', stop);
server.on('error', (error) => { console.error('Could not start search server:', error.message); process.exitCode = 1; });

try {
  let ready = false;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (server.exitCode !== null) throw new Error('Search server exited before becoming ready.');
    try {
      const response = await fetch(home, { signal: AbortSignal.timeout(500) });
      if (response.ok) { ready = true; break; }
    } catch { /* Wait for the local server to finish starting. */ }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  if (!ready) throw new Error(`Search server did not become ready at ${home}.`);

  const candidates = browserCandidates();
  const executable = candidates.find((candidate) => candidate.includes(path.sep) ? existsSync(candidate) : true);
  if (!executable) throw new Error('No supported browser was found. Install Edge or Chrome, or set BROWSER_BIN.');
  browser = spawn(executable, [`--app=${home}`], { stdio: 'ignore', windowsHide: true });
  browser.on('error', (error) => console.error('Could not open browser:', error.message));
  console.log(`Bharat Cyber Search opened at ${home}. Keep this terminal open; press Ctrl+C to stop the local server.`);
} catch (error) {
  console.error(error.message);
  stop();
  process.exitCode = 1;
}
