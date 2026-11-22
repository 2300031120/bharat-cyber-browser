const { contextBridge, ipcRenderer } = require('electron');

const listen = (channel, callback) => {
  if (typeof callback !== 'function') return () => {};
  const handler = (_event, payload) => callback(payload);
  ipcRenderer.on(channel, handler);
  return () => ipcRenderer.removeListener(channel, handler);
};

contextBridge.exposeInMainWorld('browser', Object.freeze({
  getState: () => ipcRenderer.invoke('browser:get-state'),
  createTab: () => ipcRenderer.invoke('browser:create-tab'),
  newPrivateWindow: () => ipcRenderer.invoke('browser:new-private-window'),
  closeTab: (id) => ipcRenderer.invoke('browser:close-tab', id),
  activateTab: (id) => ipcRenderer.invoke('browser:activate-tab', id),
  navigate: (value) => ipcRenderer.invoke('browser:navigate', value),
  back: () => ipcRenderer.invoke('browser:back'),
  forward: () => ipcRenderer.invoke('browser:forward'),
  reload: () => ipcRenderer.invoke('browser:reload'),
  home: () => ipcRenderer.invoke('browser:home'),
  toggleBookmark: () => ipcRenderer.invoke('browser:toggle-bookmark'),
  getBookmarks: () => ipcRenderer.invoke('browser:get-bookmarks'),
  removeBookmark: (id) => ipcRenderer.invoke('browser:remove-bookmark', id),
  getHistory: () => ipcRenderer.invoke('browser:get-history'),
  clearHistory: () => ipcRenderer.invoke('browser:clear-history'),
  openSaved: (url) => ipcRenderer.invoke('browser:open-saved', url),
  showCollection: (visible) => ipcRenderer.invoke('browser:show-collection', visible),
  onState: (callback) => listen('browser:state', callback),
  onDownload: (callback) => listen('browser:download', callback),
  onFocusAddress: (callback) => listen('browser:focus-address', callback)
}));
