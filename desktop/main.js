import { app, BrowserWindow, WebContentsView, ipcMain, protocol, net, session, dialog, Menu } from 'electron';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { Worker } from 'node:worker_threads';
import { pathToFileURL, fileURLToPath } from 'node:url';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { APP_UPDATE_INTERVAL, APP_UPDATE_REPOSITORY, shouldStartAppUpdater } from './update-policy.js';

protocol.registerSchemesAsPrivileged([{ scheme: 'app', privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true } }]);

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const windows = new Map();
const configuredSessions = new WeakSet();
let serviceWorker;
let serviceOrigin;
let profileStore;

function handleSquirrelStartup() {
  if (process.platform !== 'win32') return false;
  const event = process.argv.find((arg) => arg.startsWith('--squirrel-'));
  if (!event) return false;
  const action = event === '--squirrel-install' || event === '--squirrel-updated'
    ? '--createShortcut'
    : event === '--squirrel-uninstall' || event === '--squirrel-obsolete' ? '--removeShortcut' : null;
  const updateExe = path.resolve(path.dirname(process.execPath), '..', 'Update.exe');
  if (action && existsSync(updateExe)) {
    const updater = spawn(updateExe, [action, path.basename(process.execPath)], { detached: true, stdio: 'ignore', windowsHide: true });
    updater.unref();
  }
  app.quit();
  return true;
}

const squirrelStartup = handleSquirrelStartup();
const hasInstanceLock = squirrelStartup || app.requestSingleInstanceLock();
if (!squirrelStartup && !hasInstanceLock) app.quit();
if (!squirrelStartup && hasInstanceLock) app.on('second-instance', (_event, argv) => {
  const state = [...windows.values()].at(-1);
  if (!state) return;
  if (state.window.isMinimized()) state.window.restore();
  state.window.focus();
  const url = argv.find((arg) => /^https?:\/\//i.test(arg));
  if (url) navigate(state, url); else makeTab(state);
});

function isWebUrl(value) {
  try { return ['http:', 'https:'].includes(new URL(value).protocol); } catch { return false; }
}

function localAppUrl(query = '') { return `${serviceOrigin}/${query ? `?q=${encodeURIComponent(query)}` : ''}`; }

function resolveInput(value) {
  const text = String(value || '').trim();
  if (!text) return { type: 'home' };
  if (/^(javascript|data|file|vbscript):/i.test(text)) return { type: 'invalid' };
  if (/^https?:\/\//i.test(text)) return isWebUrl(text) ? { type: 'url', url: new URL(text).href } : { type: 'invalid' };
  if (!/\s/.test(text) && (text.includes('.') || /^localhost(?::\d+)?$/i.test(text) || /^\[[0-9a-f:]+\](?::\d+)?$/i.test(text))) {
    try {
      const url = new URL(`https://${text}`);
      return { type: 'url', url: url.href };
    } catch { return { type: 'query', query: text }; }
  }
  return { type: 'query', query: text };
}

function notify(state) {
  if (state.shell.webContents.isDestroyed()) return;
  const active = state.tabs.find((tab) => tab.id === state.activeId);
  state.shell.webContents.send('browser:state', {
    privateMode: state.privateMode,
    activeTabId: state.activeId,
    panelVisible: state.panelVisible,
    saved: Boolean(!state.privateMode && active && active.kind === 'web' && profileStore.hasBookmark(active.url)),
    tabs: state.tabs.map((tab) => {
      const url = tab.view.webContents.getURL();
      return {
        id: tab.id,
        title: tab.view.webContents.getTitle() || (tab.kind === 'internal' ? 'Cyber Search' : 'New tab'),
        address: tab.kind === 'internal' ? '' : url,
        canGoBack: tab.view.webContents.navigationHistory.canGoBack(),
        canGoForward: tab.view.webContents.navigationHistory.canGoForward(),
        loading: tab.loading,
        kind: tab.kind
      };
    })
  });
}

function setActive(state, id) {
  const tab = state.tabs.find((entry) => entry.id === id);
  if (!tab) return;
  state.activeId = id;
  for (const entry of state.tabs) {
    entry.view.setVisible(entry.id === id);
    if (entry.id === id) sizeView(state, entry.view);
    else entry.view.setBounds({ x: 0, y: 142, width: 1, height: 1 });
  }
  notify(state);
}

function sizeView(state, view) {
  const { width, height } = state.window.getContentBounds();
  view.setBounds({ x: 0, y: 142, width, height: Math.max(1, height - 142) });
}

function isInternalUrl(value) {
  try { const url = new URL(value); return url.origin === serviceOrigin; } catch { return false; }
}

function recordVisit(state, tab) {
  if (state.privateMode || tab.kind !== 'web') return;
  const url = tab.view.webContents.getURL();
  if (!isWebUrl(url) || isInternalUrl(url)) return;
  setTimeout(() => {
    if (tab.view.webContents.isDestroyed()) return;
    const title = tab.view.webContents.getTitle() || url;
    profileStore.addHistory(url, title);
  }, 600);
}

function configureSession(targetSession, privateMode, blockLocalApp) {
  if (configuredSessions.has(targetSession)) return;
  configuredSessions.add(targetSession);
  targetSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  targetSession.setPermissionCheckHandler(() => false);
  if (blockLocalApp) {
    const localHostPatterns = [`http://127.0.0.1:${new URL(serviceOrigin).port}/*`, `http://localhost:${new URL(serviceOrigin).port}/*`];
    targetSession.webRequest.onBeforeRequest({ urls: localHostPatterns }, (details, callback) => callback({ cancel: true }));
  }
  targetSession.on('will-download', async (event, item, webContents) => {
    const owner = [...windows.values()].find((state) => state.tabs.some((tab) => tab.view.webContents.id === webContents.id));
    if (!owner || owner.window.isDestroyed()) { item.cancel(); return; }
    const suggested = path.basename(item.getFilename() || 'download');
    const result = await dialog.showSaveDialog(owner.window, {
      title: 'Save download',
      defaultPath: path.join(app.getPath('downloads'), suggested),
      buttonLabel: 'Save'
    });
    if (result.canceled || !result.filePath) { item.cancel(); return; }
    item.setSavePath(result.filePath);
    item.once('done', (_downloadEvent, status) => {
      owner.shell.webContents.send('browser:download', status === 'completed' ? `Downloaded ${path.basename(result.filePath)}` : 'Download did not complete.');
    });
  });
}

function makeTab(state, { kind = 'internal', destination = localAppUrl() } = {}) {
  const targetSession = kind === 'internal' ? state.internalSession : state.browserSession;
  const view = new WebContentsView({ webPreferences: {
    session: targetSession,
    nodeIntegration: false,
    contextIsolation: true,
    sandbox: true,
    webSecurity: true,
    allowRunningInsecureContent: false,
    spellcheck: true
  } });
  const tab = { id: randomUUID(), kind, view, loading: true };
  state.tabs.push(tab);
  state.window.contentView.addChildView(view);
  view.setBounds({ x: 0, y: 142, width: 1, height: 1 });
  view.setVisible(false);
  const contents = view.webContents;
  contents.setWindowOpenHandler(({ url }) => {
    if (isWebUrl(url)) makeTab(state, { kind: 'web', destination: url });
    return { action: 'deny' };
  });
  contents.on('will-navigate', (event, url) => {
    if (!isWebUrl(url) && !isInternalUrl(url)) { event.preventDefault(); return; }
    if (tab.kind === 'internal' && !isInternalUrl(url)) {
      event.preventDefault();
      makeTab(state, { kind: 'web', destination: url });
    }
  });
  contents.on('will-redirect', (event, url) => {
    if (!isWebUrl(url) && !isInternalUrl(url)) event.preventDefault();
    if (tab.kind === 'internal' && !isInternalUrl(url)) event.preventDefault();
  });
  contents.on('did-navigate', () => { tab.loading = false; recordVisit(state, tab); notify(state); });
  contents.on('did-navigate-in-page', () => notify(state));
  contents.on('did-start-loading', () => { tab.loading = true; notify(state); });
  contents.on('did-stop-loading', () => { tab.loading = false; notify(state); });
  contents.on('page-title-updated', () => notify(state));
  contents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL, isMainFrame) => {
    if (isMainFrame && errorCode !== -3) {
      tab.loading = false;
      state.shell.webContents.send('browser:download', `Could not load ${validatedURL}: ${errorDescription}`);
      notify(state);
    }
  });
  contents.on('before-input-event', (event, input) => {
    if (input.type !== 'keyDown' || !(input.control || input.meta)) return;
    const key = input.key.toLowerCase();
    if (key === 'l') { event.preventDefault(); state.shell.webContents.send('browser:focus-address'); }
    else if (key === 't') { event.preventDefault(); makeTab(state); }
    else if (key === 'w') { event.preventDefault(); closeTab(state, tab.id); }
    else if (key === 'r') { event.preventDefault(); contents.reload(); }
  });
  setActive(state, tab.id);
  contents.loadURL(destination).catch((error) => {
    state.shell.webContents.send('browser:download', `Navigation failed: ${error.message}`);
  });
  return tab;
}

function closeTab(state, id) {
  const index = state.tabs.findIndex((tab) => tab.id === id);
  if (index < 0) return;
  const [tab] = state.tabs.splice(index, 1);
  state.window.contentView.removeChildView(tab.view);
  tab.view.webContents.close();
  if (!state.tabs.length) { makeTab(state); return; }
  if (state.activeId === id) setActive(state, state.tabs[Math.max(0, index - 1)].id);
  else notify(state);
}

function navigate(state, rawValue) {
  const destination = resolveInput(rawValue);
  const active = state.tabs.find((tab) => tab.id === state.activeId);
  if (destination.type === 'invalid') {
    state.shell.webContents.send('browser:download', 'Only website addresses and cyber-intelligence search terms are supported.');
    return;
  }
  if (destination.type === 'home') { goHome(state); return; }
  if (destination.type === 'url') {
    if (active?.kind === 'web') active.view.webContents.loadURL(destination.url).catch(() => {});
    else makeTab(state, { kind: 'web', destination: destination.url });
    return;
  }
  const home = localAppUrl(destination.query);
  if (active?.kind === 'internal') active.view.webContents.loadURL(home).catch(() => {});
  else makeTab(state, { kind: 'internal', destination: home });
}

function goHome(state) {
  const active = state.tabs.find((tab) => tab.id === state.activeId);
  if (active?.kind === 'internal') active.view.webContents.loadURL(localAppUrl()).catch(() => {});
  else makeTab(state);
}

function senderState(event) {
  const state = windows.get(event.sender.id);
  if (!state) throw new Error('Browser window is no longer available.');
  return state;
}

function registerIpc(channel, handler) {
  ipcMain.handle(channel, (event, ...args) => handler(senderState(event), ...args));
}

function createBrowserWindow({ privateMode = false } = {}) {
  const id = randomUUID();
  const win = new BrowserWindow({
    width: 1320, height: 860, minWidth: 760, minHeight: 540,
    title: privateMode ? 'Private · Bharat Cyber Browser' : 'Bharat Cyber Browser',
    backgroundColor: '#08110f',
    webPreferences: {
      preload: path.join(root, 'desktop', 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true
    }
  });
  const state = {
    id, window: win, shell: win, privateMode, panelVisible: false,
    tabs: [], activeId: null,
    browserSession: session.fromPartition(privateMode ? `private-browser-${id}` : 'persist:bharat-browser', { cache: !privateMode }),
    internalSession: session.fromPartition(privateMode ? `private-search-${id}` : 'persist:bharat-cyber-search', { cache: !privateMode })
  };
  windows.set(win.webContents.id, state);
  configureSession(state.browserSession, privateMode, true);
  configureSession(state.internalSession, privateMode, false);
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('app://shell/')) event.preventDefault();
  });
  win.on('resize', () => {
    const active = state.tabs.find((tab) => tab.id === state.activeId);
    if (active) sizeView(state, active.view);
  });
  win.on('closed', () => {
    for (const tab of state.tabs) tab.view.webContents.close();
    state.tabs.length = 0;
    windows.delete(win.webContents.id);
  });
  win.loadURL('app://shell/desktop/shell.html');
  makeTab(state);
  return state;
}

ipcMain.handle('browser:get-state', (event) => {
  const state = senderState(event);
  notify(state);
  return {
    privateMode: state.privateMode, activeTabId: state.activeId,
    panelVisible: state.panelVisible,
    saved: Boolean(state.tabs.find((tab) => tab.id === state.activeId)?.kind === 'web' && profileStore.hasBookmark(state.tabs.find((tab) => tab.id === state.activeId).view.webContents.getURL())),
    tabs: state.tabs.map((tab) => ({ id: tab.id, title: tab.view.webContents.getTitle() || 'New tab', address: tab.kind === 'internal' ? '' : tab.view.webContents.getURL(), canGoBack: tab.view.webContents.navigationHistory.canGoBack(), canGoForward: tab.view.webContents.navigationHistory.canGoForward(), loading: tab.loading, kind: tab.kind }))
  };
});
registerIpc('browser:create-tab', (state) => makeTab(state));
registerIpc('browser:new-private-window', () => { createBrowserWindow({ privateMode: true }); return true; });
registerIpc('browser:close-tab', (state, id) => closeTab(state, id));
registerIpc('browser:activate-tab', (state, id) => setActive(state, id));
registerIpc('browser:navigate', (state, value) => navigate(state, value));
registerIpc('browser:back', (state) => { const tab = state.tabs.find((entry) => entry.id === state.activeId); if (tab?.view.webContents.navigationHistory.canGoBack()) tab.view.webContents.navigationHistory.goBack(); });
registerIpc('browser:forward', (state) => { const tab = state.tabs.find((entry) => entry.id === state.activeId); if (tab?.view.webContents.navigationHistory.canGoForward()) tab.view.webContents.navigationHistory.goForward(); });
registerIpc('browser:reload', (state) => { const tab = state.tabs.find((entry) => entry.id === state.activeId); if (tab) tab.loading ? tab.view.webContents.stop() : tab.view.webContents.reload(); });
registerIpc('browser:home', (state) => goHome(state));
registerIpc('browser:toggle-bookmark', (state) => {
  if (state.privateMode) return false;
  const tab = state.tabs.find((entry) => entry.id === state.activeId);
  if (!tab || tab.kind !== 'web' || !isWebUrl(tab.view.webContents.getURL())) return false;
  const url = tab.view.webContents.getURL();
  if (profileStore.hasBookmark(url)) profileStore.removeBookmark(profileStore.listBookmarks().find((item) => item.url === url)?.id);
  else profileStore.addBookmark(url, tab.view.webContents.getTitle() || url);
  notify(state);
  return true;
});
registerIpc('browser:get-bookmarks', (state) => state.privateMode ? [] : profileStore.listBookmarks());
registerIpc('browser:remove-bookmark', (state, id) => state.privateMode ? [] : profileStore.removeBookmark(id));
registerIpc('browser:get-history', (state) => state.privateMode ? [] : profileStore.listHistory());
registerIpc('browser:clear-history', (state) => { if (!state.privateMode) profileStore.clearHistory(); return true; });
registerIpc('browser:open-saved', (state, url) => navigate(state, url));
registerIpc('browser:show-collection', (state, visible) => { state.panelVisible = Boolean(visible); notify(state); });

async function startLocalService() {
  const workerEntry = app.isPackaged
    ? path.join(process.resourcesPath, 'app.asar.unpacked', 'desktop', 'server-worker.js')
    : new URL('./server-worker.js', import.meta.url);
  serviceWorker = new Worker(workerEntry);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Local cyber search service did not start in time.')), 30000);
    serviceWorker.on('message', (message) => {
      if (message.type === 'ready') { clearTimeout(timer); resolve(`http://127.0.0.1:${message.port}`); }
      else if (message.type === 'error') { clearTimeout(timer); reject(new Error(message.message)); }
    });
    serviceWorker.once('error', (error) => { clearTimeout(timer); reject(error); });
    serviceWorker.on('exit', (code) => { if (code !== 0) { clearTimeout(timer); reject(new Error(`Local cyber search worker exited (${code}).`)); } });
  });
}

if (!squirrelStartup && hasInstanceLock) app.whenReady().then(async () => {
  try {
  profileStore = await import('../browser-store.js');
  if (process.platform === 'win32') app.setAppUserModelId('com.squirrel.BharatCyberBrowser.BharatCyberBrowser');
  if (shouldStartAppUpdater({ isPackaged: app.isPackaged, platform: process.platform, argv: process.argv })) {
    try {
      const { updateElectronApp, UpdateSourceType } = await import('update-electron-app');
      updateElectronApp({
        updateSource: { type: UpdateSourceType.ElectronPublicUpdateService, repo: APP_UPDATE_REPOSITORY },
        updateInterval: APP_UPDATE_INTERVAL,
        notifyUser: true
      });
    } catch (error) {
      console.error('Bharat Cyber Browser update check could not start:', error.message);
    }
  }
  protocol.handle('app', async (request) => {
    try {
      const url = new URL(request.url);
      const relative = decodeURIComponent(url.pathname).replace(/^\/+/, '');
      const file = path.resolve(root, relative);
      const rel = path.relative(root, file);
      if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return new Response('Not found', { status: 404 });
      return net.fetch(pathToFileURL(file).href);
    } catch { return new Response('Not found', { status: 404 }); }
  });
  serviceOrigin = await startLocalService();
  const template = [
    { label: 'File', submenu: [
      { label: 'New tab', accelerator: 'CmdOrCtrl+T', click: () => { const state = [...windows.values()].at(-1); if (state) makeTab(state); } },
      { label: 'New private window', accelerator: 'CmdOrCtrl+Shift+N', click: () => createBrowserWindow({ privateMode: true }) },
      { type: 'separator' }, { role: 'quit' }
    ] },
    { label: 'Edit', submenu: [{ role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
    { label: 'View', submenu: [{ role: 'reload' }, { role: 'toggleDevTools' }, { type: 'separator' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { role: 'resetZoom' }] }
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
  createBrowserWindow();
  } catch (error) {
    dialog.showErrorBox('Bharat Cyber Browser could not start', error.message);
    app.quit();
  }
});

app.on('before-quit', () => {
  serviceWorker?.postMessage({ type: 'stop' });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (windows.size === 0 && serviceOrigin) createBrowserWindow(); });
