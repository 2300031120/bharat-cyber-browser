const $ = (selector) => document.querySelector(selector);
const tabs = [...document.querySelectorAll('.tab')];
const intelView = $('#intel-view');
const assetView = $('#asset-view');
const intelResults = $('#intel-results');
const assetResults = $('#asset-results');
const intelForm = $('#intel-form');
const assetForm = $('#asset-form');
let syncTimer;

const glossary = {
  en: [
    ['Vulnerability', 'A software weakness that could affect security.'],
    ['Severity', 'The estimated technical impact reported by the source.'],
    ['Known exploited', 'CISA lists evidence that attackers are exploiting this vulnerability.']
  ],
  te: [
    ['లోపం (Vulnerability)', 'భద్రతపై ప్రభావం చూపగల సాఫ్ట్‌వేర్ లోపం.'],
    ['తీవ్రత (Severity)', 'మూలం తెలిపిన సాంకేతిక ప్రభావ అంచనా.'],
    ['దాడుల్లో వాడుతున్నారు (Known exploited)', 'దాడి చేసేవారు ఈ లోపాన్ని ఉపయోగిస్తున్నారని CISA జాబితా చేసింది.']
  ],
  hi: [
    ['कमज़ोरी (Vulnerability)', 'सॉफ़्टवेयर की ऐसी कमी जो सुरक्षा को प्रभावित कर सकती है।'],
    ['गंभीरता (Severity)', 'स्रोत द्वारा बताया गया तकनीकी प्रभाव का अनुमान।'],
    ['हमलों में इस्तेमाल (Known exploited)', 'CISA के अनुसार हमलावर इस कमज़ोरी का फायदा उठा रहे हैं।']
  ]
};

function renderGlossary() {
  const language = $('#glossary-language').value;
  const terms = glossary[language] || glossary.en;
  const list = $('#glossary-terms');
  list.replaceChildren();
  for (const [term, definition] of terms) {
    addText(list, 'dt', '', term);
    addText(list, 'dd', '', definition);
  }
  $('.glossary summary')?.replaceChildren(document.createTextNode(`Security terms · ${$('#glossary-language').selectedOptions[0].textContent}`));
}
$('#glossary-language').addEventListener('change', renderGlossary);
renderGlossary();

function setTab(name) {
  tabs.forEach((tab) => tab.classList.toggle('active', tab.dataset.tab === name));
  intelView.classList.toggle('hidden', name !== 'intel');
  assetView.classList.toggle('hidden', name !== 'asset');
}
tabs.forEach((tab) => tab.addEventListener('click', () => setTab(tab.dataset.tab)));

function addText(parent, tag, className, content) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = content ?? '';
  parent.append(element);
  return element;
}

function prettyDate(value) {
  if (!value) return 'Date unavailable';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Date unavailable' : date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function showMessage(target, title, body) {
  target.replaceChildren();
  const card = document.createElement('div');
  card.className = 'empty-card';
  addText(card, 'strong', '', title);
  addText(card, 'span', '', body);
  target.append(card);
}

async function loadSyncStatus() {
  try {
    const response = await fetch('/api/sync/status', { cache: 'no-store' });
    if (!response.ok) throw new Error('Status unavailable');
    const status = await response.json();
    $('#record-count').textContent = Number(status.index?.total || 0).toLocaleString();
    const sources = status.sources || [];
    const ready = sources.filter((source) => source.status === 'ready').length;
    $('#source-count').textContent = `${ready}/${Math.max(5, sources.length)}`;
    $('#last-sync').textContent = status.lastSync ? prettyDate(status.lastSync) : 'Not synced yet';
    const sourceList = $('#source-list');
    sourceList.replaceChildren();
    for (const source of sources) {
      const chip = document.createElement('span');
      chip.className = `source-chip ${source.status === 'ready' ? 'ready' : source.status === 'error' ? 'error' : source.status === 'syncing' ? 'syncing' : 'pending'}`;
      chip.title = source.error || `${source.records || 0} records`;
      addText(chip, 'i', '', '');
      addText(chip, 'span', '', source.source);
      if (source.status === 'error' && source.error) addText(chip, 'span', 'source-error', source.error);
      sourceList.append(chip);
    }
    const cveBuilding = sources.some((source) => source.source === 'CVE List' && source.status === 'syncing');
    $('#partial-index-note').classList.toggle('hidden', !cveBuilding);
    const sourceSyncing = sources.some((source) => source.status === 'syncing');
    const isSyncing = Boolean(status.running || sourceSyncing);
    const progress = $('#sync-progress');
    progress.classList.toggle('hidden', !isSyncing);
    $('#sync-button').disabled = isSyncing;
    $('#sync-message').textContent = isSyncing
      ? status.running
        ? `Updating ${status.currentSource || 'public sources'}${status.currentPhase ? ` · ${status.currentPhase}` : ''}${status.currentYear ? ` · ${status.currentYear}` : ''}${status.currentCount ? ` · ${Number(status.currentCount).toLocaleString()} processed` : '…'}`
        : 'An update is running in another local process. Search remains available.'
      : status.lastError || '';
    if (isSyncing) {
      clearTimeout(syncTimer);
      syncTimer = setTimeout(loadSyncStatus, 1100);
    } else {
      clearTimeout(syncTimer);
      syncTimer = null;
    }
  } catch {
    $('#sync-message').textContent = 'Could not load local index status.';
  }
}

async function startSync() {
  const button = $('#sync-button');
  button.disabled = true;
  try {
    await fetch('/api/sync', { method: 'POST' });
    await loadSyncStatus();
  } catch {
    $('#sync-message').textContent = 'Could not start the update. Try again.';
    button.disabled = false;
  }
}
$('#sync-button').addEventListener('click', startSync);

function resultCard(item) {
  const article = document.createElement('article');
  article.className = 'result-card';
  const heading = document.createElement('div');
  heading.className = 'result-card-top';
  const kindLabel = item.kind === 'certin' ? 'CERT-In' : item.kind === 'attack' ? 'MITRE ATT&CK' : item.kind === 'kev' ? 'CISA KEV' : 'CVE';
  addText(heading, 'span', `kind-badge kind-${item.kind}`, kindLabel);
  if (item.severity) addText(heading, 'span', `severity-badge severity-${item.severity.toLowerCase()}`, item.severity);
  if (item.kev) addText(heading, 'span', 'kev-badge', 'KNOWN EXPLOITED');
  article.append(heading);
  const anchor = document.createElement('a');
  anchor.className = 'result-title';
  try {
    const safeUrl = new URL(item.sourceUrl);
    if (!['http:', 'https:'].includes(safeUrl.protocol)) throw new Error('Unsafe URL');
    anchor.href = safeUrl.href;
    anchor.target = '_blank';
    anchor.rel = 'noopener noreferrer';
  } catch { anchor.href = '#'; }
  anchor.textContent = item.title;
  article.append(anchor);
  addText(article, 'p', 'result-summary', item.summary || 'No description is available.');
  const meta = document.createElement('div');
  meta.className = 'result-meta';
  const data = [item.source, item.publishedAt ? prettyDate(item.publishedAt) : '', item.vendor, item.product, item.techniqueId].filter(Boolean);
  addText(meta, 'span', '', data.join(' · '));
  article.append(meta);
  if (item.kind === 'cve' || item.kind === 'kev') {
    const context = document.createElement('details');
    context.className = 'triage-context';
    addText(context, 'summary', '', 'View triage context');
    const body = document.createElement('div');
    body.className = 'triage-context-body';
    if (item.kev) {
      addText(body, 'strong', '', 'Exploit signal');
      addText(body, 'p', '', 'CISA lists this vulnerability as known exploited.');
    }
    if (item.severityScore != null) {
      addText(body, 'strong', '', 'Severity from source');
      addText(body, 'p', '', `${item.severity || 'Rated'} · CVSS ${Number(item.severityScore).toFixed(1)}. See the linked record for its scoring details.`);
    } else if (item.severity) {
      addText(body, 'strong', '', 'Severity from source');
      addText(body, 'p', '', `${item.severity}. The source did not provide a numeric score in this index.`);
    }
    addText(body, 'strong', '', 'Next check');
    addText(body, 'p', '', 'Confirm the affected product and version in the linked official record and vendor advisory before deciding on a fix.');
    context.append(body);
    article.append(context);
  }
  return article;
}

async function searchIntel(event) {
  event.preventDefault();
  const query = $('#intel-query').value.trim();
  if (!query) return;
  intelResults.replaceChildren();
  $('#result-title').textContent = `Searching for “${query}”`;
  $('#result-count').textContent = 'Searching local index…';
  try {
    const params = new URLSearchParams({ q: query, kind: $('#kind-filter').value });
    if ($('#severity-filter').value) params.set('severity', $('#severity-filter').value);
    if ($('#kev-filter').checked) params.set('kev', '1');
    const response = await fetch(`/api/search?${params}`, { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Search failed.');
    $('#result-title').textContent = `Results for “${query}”`;
    $('#result-count').textContent = `${data.total.toLocaleString()} matches · local`;
    if (!data.results.length) {
      showMessage(intelResults, 'No local matches', data.total === 0 && !Number($('#record-count').textContent.replaceAll(',', ''))
        ? 'Sync the free public intelligence sources to build your local index.'
        : 'Try a CVE ID, product name, technique ID, or broader keyword.');
      return;
    }
    for (const item of data.results) intelResults.append(resultCard(item));
  } catch (error) {
    showMessage(intelResults, 'Search unavailable', error.message);
    $('#result-count').textContent = '';
  }
}
intelForm.addEventListener('submit', searchIntel);
$('#kind-filter').addEventListener('change', () => { if ($('#intel-query').value.trim()) intelForm.requestSubmit(); });
$('#severity-filter').addEventListener('change', () => { if ($('#intel-query').value.trim()) intelForm.requestSubmit(); });
$('#kev-filter').addEventListener('change', () => { if ($('#intel-query').value.trim()) intelForm.requestSubmit(); });

function assetSection(title, label) {
  const section = document.createElement('section');
  section.className = 'asset-section';
  addText(section, 'h3', '', title);
  if (label) addText(section, 'div', 'asset-source', label);
  return section;
}

function renderAssetResult(data) {
  assetResults.replaceChildren();
  const header = document.createElement('div');
  header.className = 'asset-result-header';
  addText(header, 'span', 'kind-badge kind-asset', data.type === 'domain' ? 'DOMAIN' : 'PUBLIC IP');
  addText(header, 'h2', '', data.target);
  addText(header, 'p', 'asset-disclosed', `Sent to: ${data.disclosedTo.join(', ')}`);
  assetResults.append(header);

  if (data.type === 'domain') {
    const certs = assetSection('Certificate transparency', 'crt.sh');
    if (!data.certificates?.length) addText(certs, 'p', 'muted', 'No matching certificates returned.');
    for (const cert of data.certificates || []) {
      const row = document.createElement('div'); row.className = 'asset-row';
      addText(row, 'strong', '', cert.name);
      addText(row, 'span', '', `${cert.issuer || 'Issuer unavailable'} · ${prettyDate(cert.notBefore)}`);
      certs.append(row);
    }
    assetResults.append(certs);

    const dns = assetSection('DNS records', 'Google Public DNS');
    for (const [type, values] of Object.entries(data.dns || {})) {
      if (!values.length) continue;
      const row = document.createElement('div'); row.className = 'dns-row';
      addText(row, 'strong', '', type);
      addText(row, 'span', '', values.map((value) => value.data).join(' · '));
      dns.append(row);
    }
    if (!dns.querySelector('.dns-row')) addText(dns, 'p', 'muted', 'No DNS answers returned.');
    assetResults.append(dns);
  }

  const rdap = assetSection('Registration data', 'RDAP');
  if (data.rdap) {
    const fields = [['Name', data.rdap.name], ['Handle', data.rdap.handle], ['Country', data.rdap.country], ['Network', data.rdap.startAddress && data.rdap.endAddress ? `${data.rdap.startAddress} – ${data.rdap.endAddress}` : ''], ['Status', (data.rdap.status || []).join(', ')], ['Nameservers', (data.rdap.nameservers || []).join(', ')]];
    for (const [name, value] of fields.filter(([, value]) => value)) {
      const row = document.createElement('div'); row.className = 'dns-row';
      addText(row, 'strong', '', name); addText(row, 'span', '', value); rdap.append(row);
    }
    if (data.rdap.sourceUrl) {
      const source = document.createElement('a'); source.href = data.rdap.sourceUrl; source.target = '_blank'; source.rel = 'noopener noreferrer'; source.className = 'source-link'; source.textContent = 'Open RDAP record →'; rdap.append(source);
    }
  } else addText(rdap, 'p', 'muted', 'RDAP data unavailable.');
  assetResults.append(rdap);

  if (data.errors?.length) {
    const errors = document.createElement('div'); errors.className = 'partial-warning';
    addText(errors, 'strong', '', 'Some sources did not respond:');
    addText(errors, 'span', '', data.errors.map((item) => item.source).join(', '));
    assetResults.append(errors);
  }
}

function updateAssetButton() {
  $('#asset-submit').disabled = !$('#asset-consent').checked || !$('#asset-target').value.trim();
}
$('#asset-consent').addEventListener('change', updateAssetButton);
$('#asset-target').addEventListener('input', updateAssetButton);
assetForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!$('#asset-consent').checked) return;
  const target = $('#asset-target').value.trim();
  $('#asset-status').textContent = 'Running passive public-data lookups…';
  assetResults.replaceChildren();
  try {
    const response = await fetch('/api/assets/lookup', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target, confirmed: true }), cache: 'no-store'
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Lookup failed.');
    renderAssetResult(data);
    $('#asset-status').textContent = 'Lookup complete. Target was not contacted or scanned.';
  } catch (error) {
    $('#asset-status').textContent = error.message;
  }
});

if ('serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));

await loadSyncStatus();
const initialQuery = new URLSearchParams(window.location.search).get('q');
if (initialQuery) {
  $('#intel-query').value = initialQuery.slice(0, 300);
  intelForm.requestSubmit();
}
const currentStatus = await fetch('/api/sync/status', { cache: 'no-store' }).then((response) => response.json()).catch(() => null);
const lastUpdate = currentStatus?.lastSync ? Date.parse(currentStatus.lastSync) : 0;
const sourceSyncing = currentStatus?.sources?.some((source) => source.status === 'syncing');
if (!currentStatus?.running && !sourceSyncing && (!lastUpdate || Date.now() - lastUpdate > 24 * 60 * 60 * 1000)) startSync();
