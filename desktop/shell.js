const $ = (selector) => document.querySelector(selector);
const tabsElement = $('#tabs');
const address = $('#address');
const panel = $('#collection-panel');
let state = { tabs: [], activeTabId: null, privateMode: false, saved: false, panelVisible: false };
let panelMode = null;

function makeButton(label, title, onClick, className = '') {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  button.title = title;
  if (className) button.className = className;
  button.addEventListener('click', onClick);
  return button;
}

function renderTabs() {
  tabsElement.replaceChildren();
  for (const tab of state.tabs) {
    const button = document.createElement('div');
    button.className = `tab${tab.id === state.activeTabId ? ' active' : ''}`;
    button.setAttribute('role', 'tab');
    button.setAttribute('aria-selected', String(tab.id === state.activeTabId));
    button.tabIndex = 0;
    button.addEventListener('click', () => window.browser.activateTab(tab.id));
    button.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') window.browser.activateTab(tab.id); });
    const title = document.createElement('span');
    title.className = 'tab-title';
    title.textContent = `${tab.loading ? '◌ ' : ''}${tab.title || 'New tab'}`;
    button.append(title);
    button.append(makeButton('×', 'Close tab', (event) => {
      event.stopPropagation?.();
      window.browser.closeTab(tab.id);
    }, 'tab-close'));
    tabsElement.append(button);
  }
  const active = state.tabs.find((tab) => tab.id === state.activeTabId);
  if (active && document.activeElement !== address) address.value = active.address || '';
  $('#back').disabled = !active?.canGoBack;
  $('#forward').disabled = !active?.canGoForward;
  $('#reload').textContent = active?.loading ? '×' : '↻';
  $('#bookmark').textContent = state.saved ? '★' : '☆';
  $('#bookmark').title = state.saved ? 'Remove bookmark' : 'Bookmark this page';
  document.title = `${state.privateMode ? 'Private · ' : ''}${active?.title || 'Bharat Cyber Browser'}`;
}

function renderCollection(mode, items) {
  panel.replaceChildren();
  panel.classList.remove('hidden');
  if (mode === 'history') {
    panel.append(makeButton('Clear history', 'Clear local browsing history', async () => {
      await window.browser.clearHistory();
      renderCollection('history', await window.browser.getHistory());
    }));
  }
  if (!items.length) {
    const empty = document.createElement('span');
    empty.className = 'empty';
    empty.textContent = mode === 'history' ? 'No saved browsing history.' : 'No bookmarks yet.';
    panel.append(empty);
    return;
  }
  for (const item of items) {
    const label = item.title || item.url;
    panel.append(makeButton(label, item.url, async () => {
      panel.classList.add('hidden');
      await window.browser.openSaved(item.url);
    }));
    if (mode === 'bookmarks') panel.append(makeButton('×', 'Remove bookmark', async () => {
      await window.browser.removeBookmark(item.id);
      renderCollection('bookmarks', await window.browser.getBookmarks());
    }));
  }
}

window.browser.onState((next) => {
  state = next;
  renderTabs();
  if (!state.panelVisible) panel.classList.add('hidden');
});
window.browser.onDownload((message) => {
  const notice = $('#download-notice');
  notice.textContent = message;
  notice.classList.remove('hidden');
  setTimeout(() => notice.classList.add('hidden'), 5000);
});
window.browser.onFocusAddress(() => { address.focus(); address.select(); });

$('#new-tab').addEventListener('click', () => window.browser.createTab());
$('#private-window').addEventListener('click', () => window.browser.newPrivateWindow());
$('#back').addEventListener('click', () => window.browser.back());
$('#forward').addEventListener('click', () => window.browser.forward());
$('#reload').addEventListener('click', () => window.browser.reload());
$('#home').addEventListener('click', () => window.browser.home());
$('#bookmark').addEventListener('click', () => window.browser.toggleBookmark());
$('#bookmarks').addEventListener('click', async () => {
  panelMode = panelMode === 'bookmarks' && !panel.classList.contains('hidden') ? null : 'bookmarks';
  if (!panelMode) panel.classList.add('hidden');
  else renderCollection(panelMode, await window.browser.getBookmarks());
});
$('#history').addEventListener('click', async () => {
  panelMode = panelMode === 'history' && !panel.classList.contains('hidden') ? null : 'history';
  if (!panelMode) panel.classList.add('hidden');
  else renderCollection(panelMode, await window.browser.getHistory());
});
$('#address-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const value = address.value.trim();
  if (!value) return;
  await window.browser.navigate(value);
  address.blur();
});
panel.addEventListener('mouseenter', () => window.browser.showCollection(true));
panel.addEventListener('mouseleave', () => window.browser.showCollection(false));
window.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'l') { event.preventDefault(); address.focus(); address.select(); }
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 't') { event.preventDefault(); window.browser.createTab(); }
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'w') { event.preventDefault(); window.browser.closeTab(state.activeTabId); }
  if (event.key === 'Escape') { panel.classList.add('hidden'); window.browser.showCollection(false); }
});
window.browser.getState().then((next) => { state = next; renderTabs(); });
