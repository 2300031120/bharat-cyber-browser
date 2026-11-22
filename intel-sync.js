import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, readdir, readFile, rm, rename, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import { dataDirectory, acquireSyncLease, beginSourceImport, cveYearCounts, getSyncLease, importSourceBatch, finishSourceImport, getAppMeta, removeIntelRecords, releaseSyncLease, setAppMeta, setSourceStatus, sourceStatuses, updateSyncLease, lastSync, setLastSync, indexStats } from './intel-store.js';

const execFileAsync = promisify(execFile);
const CVE_REPOSITORY = 'https://github.com/CVEProject/cvelistV5.git';
const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const ATTACK_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json';
const CERT_IN_HOME = 'https://www.cert-in.org.in/s2cMainServlet?pageid=PUBWEL01';
const CERT_IN_ADVISORIES = (year) => `https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST02&year=${year}`;
const now = () => new Date().toISOString();
const STALE_GIT_LOCK_AGE_MS = 30 * 60 * 1000;
let state = { running: false, currentSource: null, currentPhase: null, currentYear: null, currentCount: 0, startedAt: null, lastError: null };

async function hasActiveGitProcess() {
  if (process.platform === 'win32') {
    const script = "$ErrorActionPreference='Stop'; try { $git = Get-Process -Name 'git*' -ErrorAction SilentlyContinue; if ($git) { exit 10 }; exit 0 } catch { exit 20 }";
    try {
      await execFileAsync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, timeout: 10000 });
      return false;
    } catch (error) {
      if (error.code === 10) return true;
      throw new Error('Could not check for active Git operations. No lock files were removed; close Git tools and retry.');
    }
  }
  try {
    const { stdout } = await execFileAsync('ps', ['-eo', 'comm='], { timeout: 10000 });
    return stdout.split(/\r?\n/).some((name) => /^git(?:[-.]|$)/i.test(name.trim()));
  } catch {
    throw new Error('Could not check for active Git operations. No lock files were removed; close Git tools and retry.');
  }
}

async function removeStaleGitLocks(repo, partial) {
  const lockPaths = [repo, partial].flatMap((checkout) => [
    path.join(checkout, '.git', 'index.lock'),
    path.join(checkout, '.git', 'info', 'sparse-checkout.lock')
  ]);
  const stale = [];
  for (const lockPath of lockPaths) {
    try {
      const details = await stat(lockPath);
      if (!details.isFile()) continue;
      if (Date.now() - details.mtimeMs < STALE_GIT_LOCK_AGE_MS) {
        throw new Error(`A Git lock is newer than 30 minutes, so it was left untouched: ${lockPath}. Close the Git operation and retry after it finishes.`);
      }
      stale.push(lockPath);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  if (!stale.length) return;
  if (await hasActiveGitProcess()) {
    throw new Error(`An active Git process was found. The old CVE checkout lock was left untouched: ${stale[0]}. Close Git operations and retry.`);
  }
  for (const lockPath of stale) {
    try {
      const latest = await stat(lockPath);
      if (Date.now() - latest.mtimeMs < STALE_GIT_LOCK_AGE_MS) {
        throw new Error(`The Git lock changed while checking it and was left untouched: ${lockPath}. Retry after Git finishes.`);
      }
      await unlink(lockPath);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
}

async function fetchResponse(url, options = {}) {
  const { timeout = 30000, ...requestOptions } = options;
  const response = await fetch(url, {
    ...requestOptions,
    headers: { 'user-agent': 'BharatCyberSearch/0.1 (local personal research tool)', accept: 'application/json,text/html;q=0.9,*/*;q=0.8', ...options.headers },
    signal: AbortSignal.timeout(timeout)
  });
  if (!response.ok) throw new Error(`Source returned HTTP ${response.status}`);
  return response;
}

async function importRecords(source, records) {
  if (!records.length) throw new Error('No records received; existing index was kept.');
  beginSourceImport();
  for (let i = 0; i < records.length; i += 400) {
    importSourceBatch(records.slice(i, i + 400));
    if (i && i % 4000 === 0) await new Promise((resolve) => setImmediate(resolve));
  }
  return finishSourceImport(source);
}

async function importRecordStream(source, records, { scope = '', year = null } = {}) {
  beginSourceImport(scope);
  state.currentPhase = 'indexing year';
  state.currentYear = year == null ? null : String(year);
  state.currentCount = 0;
  let batch = [];
  let count = 0;
  for await (const record of records) {
    batch.push(record);
    if (batch.length === 400) {
      importSourceBatch(batch, scope);
      count += batch.length;
      state.currentCount = count;
      batch = [];
      if (count % 4000 === 0) {
        state.currentCount = count;
        await new Promise((resolve) => setImmediate(resolve));
      }
    }
  }
  if (batch.length) { importSourceBatch(batch, scope); count += batch.length; state.currentCount = count; }
  if (!count) throw new Error('No records received; existing index was kept.');
  return finishSourceImport(source, scope, year);
}

function severityFromCve(cve) {
  const metrics = cve.containers?.cna?.metrics || [];
  let selected = null;
  for (const metric of metrics) {
    for (const key of ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']) {
      const score = metric?.[key]?.baseScore;
      if (Number.isFinite(score) && (!selected || score > selected.score)) {
        selected = { score, label: metric[key].baseSeverity || metric[key].severity || severityLabel(score) };
      }
    }
  }
  return selected || {};
}

function severityLabel(score) {
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
}

function cveRecord(cve) {
  const id = cve.cveMetadata?.cveId;
  if (!id) return null;
  const cna = cve.containers?.cna || {};
  const descriptions = cna.descriptions || [];
  const description = descriptions.find((item) => item.lang === 'en')?.value || descriptions[0]?.value || '';
  const affected = cna.affected || [];
  const vendors = [...new Set(affected.map((item) => item.vendor).filter(Boolean))].slice(0, 8);
  const products = [...new Set(affected.flatMap((item) => (item.product ? [item.product] : [])).filter(Boolean))].slice(0, 12);
  const cwes = (cna.problemTypes || []).flatMap((problem) => problem.descriptions || []).map((item) => item.cweId).filter(Boolean);
  const metrics = severityFromCve(cve);
  return {
    record_id: `cve:${id}`, kind: 'cve', identifier: id,
    title: `${id}${products[0] ? ` · ${products[0]}` : ''}`,
    summary: [description, vendors.length ? `Vendor: ${vendors.join(', ')}` : '', products.length ? `Products: ${products.join(', ')}` : '', cwes.length ? `Weaknesses: ${[...new Set(cwes)].join(', ')}` : ''].filter(Boolean).join(' '),
    source_name: 'CVE List', source_url: `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`,
    published_at: cve.cveMetadata?.datePublished || cve.cveMetadata?.dateUpdated || null,
    severity_score: metrics.score, severity_label: metrics.label, is_kev: false,
    vendor: vendors.join(' '), product: products.join(' '), technique_id: null
  };
}

async function* walkJsonFiles(directory) {
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) yield* walkJsonFiles(full);
    else if (entry.isFile() && /^CVE-\d{4}-\d+\.json$/i.test(entry.name)) yield full;
  }
}

async function ensureCveRepo() {
  const repo = path.join(dataDirectory(), 'cvelistV5');
  const years = cveYearsToIndex();
  const sparsePaths = years.map((year) => `cves/${year}`);
  const partial = `${repo}.partial`;
  await mkdir(dataDirectory(), { recursive: true });
  await removeStaleGitLocks(repo, partial);
  let exists = false;
  try {
    await execFileAsync('git', ['-C', repo, 'rev-parse', '--is-inside-work-tree'], { windowsHide: true });
    exists = true;
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error('Git is required to sync the CVE List. Install Git and try again.');
  }
  if (!exists) {
    try {
      await stat(repo);
      throw new Error('CVE sync cannot use its data folder because it exists but is not a Git checkout. Rename that folder and retry.');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  const runGit = (stage, args, timeout = 1800000) => new Promise((resolve, reject) => {
    let stderr = '';
    let timedOut = false;
    const child = spawn('git', args, { windowsHide: true, detached: process.platform !== 'win32', stdio: ['ignore', 'ignore', 'pipe'] });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => { stderr = `${stderr}${chunk}`.slice(-12000); });
    const timer = setTimeout(() => {
      timedOut = true;
      if (process.platform === 'win32') {
        execFile('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true }, () => {});
      } else {
        try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
      }
    }, timeout);
    child.once('error', (error) => {
      clearTimeout(timer);
      if (error.code === 'ENOENT') reject(new Error('Git is required to sync the CVE List. Install Git and restart the app.'));
      else reject(new Error(`CVE sync ${stage} could not start: ${error.message}`));
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      if (timedOut) return reject(new Error(`CVE sync ${stage} timed out after ${Math.round(timeout / 60000)} minutes. The temporary checkout is kept so the next sync can resume.`));
      if (code !== 0) {
        const gitLock = stderr.match(/(sparse-checkout\.lock|index\.lock)/)?.[1];
        const detail = gitLock && stderr.includes('File exists')
          ? `A previous interrupted Git operation left a stale ${gitLock}. Close other Git operations, delete cvelistV5.partial/.git/${gitLock === 'sparse-checkout.lock' ? 'info/' : ''}${gitLock}, then retry. The partial CVE checkout is preserved.`
          : stderr.replaceAll(repo, '<CVE data folder>').replaceAll(partial, '<temporary CVE folder>')
          .replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(-220);
        return reject(new Error(`CVE sync ${stage} failed (Git exit ${code}): ${detail || 'Git returned no details.'}`));
      }
      resolve();
    });
  });
  state.currentPhase = exists ? 'updating CVE repository' : 'checking CVE repository';
  let previousHead = null;
  if (exists) {
    previousHead = (await execFileAsync('git', ['-C', repo, 'rev-parse', 'HEAD'], { windowsHide: true })).stdout.trim();
    await runGit('sparse-checkout update', ['-C', repo, 'sparse-checkout', 'set', ...sparsePaths]);
    await runGit('repository update', ['-C', repo, 'pull', '--ff-only']);
  } else {
    let partialReady = false;
    try {
      await execFileAsync('git', ['-C', partial, 'rev-parse', '--is-inside-work-tree'], { windowsHide: true });
      partialReady = true;
    } catch (error) {
      if (error.code === 'ENOENT') throw new Error('Git is required to sync the CVE List. Install Git and restart the app.');
      try { await stat(partial); await rm(partial, { recursive: true, force: true }); } catch (statError) { if (statError.code !== 'ENOENT') throw statError; }
    }
    if (partialReady) previousHead = (await execFileAsync('git', ['-C', partial, 'rev-parse', 'HEAD'], { windowsHide: true })).stdout.trim();
    if (!partialReady) await runGit('clone', ['clone', '--depth=1', '--filter=blob:none', '--sparse', CVE_REPOSITORY, partial]);
    await runGit('sparse-checkout setup', ['-C', partial, 'sparse-checkout', 'set', ...sparsePaths]);
    if (partialReady) await runGit('repository update', ['-C', partial, 'pull', '--ff-only']);
    else await runGit('checkout', ['-C', partial, 'checkout']);
    try {
      await rename(partial, repo);
    } catch (error) {
      if (!['EPERM', 'EBUSY'].includes(error.code)) throw error;
      try {
        await stat(repo);
        throw error;
      } catch (destinationError) {
        if (destinationError.code !== 'ENOENT') throw destinationError;
      }
      // Windows may temporarily prevent renaming a populated checkout. It is
      // still a valid sparse Git repo, so index it in place and resume there.
      const head = (await execFileAsync('git', ['-C', partial, 'rev-parse', 'HEAD'], { windowsHide: true })).stdout.trim();
      return { repo: partial, years, head, previousHead };
    }
  }
  const head = (await execFileAsync('git', ['-C', repo, 'rev-parse', 'HEAD'], { windowsHide: true })).stdout.trim();
  return { repo, years, head, previousHead };
}

async function* cveRecordStream(repo, years) {
  let parsed = 0;
  for (const year of years) {
    for await (const file of walkJsonFiles(path.join(repo, 'cves', year))) {
      try {
        const record = cveRecord(JSON.parse(await readFile(file, 'utf8')));
        if (record) yield record;
      } catch { /* Ignore malformed or withdrawn source files and continue indexing the rest. */ }
      parsed += 1;
      if (parsed % 4000 === 0) await new Promise((resolve) => setImmediate(resolve));
    }
  }
}

export function cveYearsToIndex(currentYear = new Date().getUTCFullYear()) {
  return Array.from({ length: 6 }, (_, index) => String(currentYear - index));
}

export function parseCveDiff(stdout, repo, year) {
  const tokens = stdout.split('\0');
  const changes = [];
  for (let index = 0; index + 1 < tokens.length; index += 2) {
    const status = tokens[index];
    const file = tokens[index + 1];
    if (!file || !/^[AMD]$/.test(status)) continue;
    const normalized = file.replaceAll('\\', '/');
    if (!normalized.startsWith(`cves/${year}/`) || !/^cves\/\d{4}\/(?:[^/]+\/)*CVE-\d{4}-\d+\.json$/i.test(normalized)) continue;
    changes.push({ status, file: path.join(repo, ...normalized.split('/')) });
  }
  return changes;
}

async function changedCveFiles(repo, fromCommit, toCommit, year) {
  const { stdout } = await execFileAsync('git', [
    '-C', repo, 'diff', '--name-status', '-z', '--no-renames',
    fromCommit, toCommit, '--', `cves/${year}/`
  ], { windowsHide: true, maxBuffer: 64 * 1024 * 1024, encoding: 'utf8' });
  return parseCveDiff(stdout, repo, year);
}

async function applyChangedCveFiles(repo, year, changes) {
  state.currentPhase = 'applying changed CVE files';
  state.currentYear = String(year);
  state.currentCount = 0;
  let processed = 0;
  let records = [];
  let removals = [];
  const flush = () => {
    if (records.length) importSourceBatch(records, String(year), false);
    if (removals.length) removeIntelRecords(removals);
    records = [];
    removals = [];
  };

  for (const change of changes) {
    const fileName = path.basename(change.file);
    const identifier = fileName.replace(/\.json$/i, '').toUpperCase();
    if (change.status === 'D') removals.push(`cve:${identifier}`);
    else {
      try {
        const record = cveRecord(JSON.parse(await readFile(change.file, 'utf8')));
        if (record && record.identifier.toUpperCase() === identifier) records.push(record);
        else removals.push(`cve:${identifier}`);
      } catch (error) {
        if (error.code === 'ENOENT') removals.push(`cve:${identifier}`);
        else throw error;
      }
    }
    processed += 1;
    if (records.length + removals.length >= 400) {
      flush();
      state.currentCount = processed;
      if (processed % 4000 === 0) await new Promise((resolve) => setImmediate(resolve));
    }
  }
  flush();
  state.currentCount = processed;
  return processed;
}

async function syncCveList() {
  const { repo, years, head, previousHead } = await ensureCveRepo();
  let checkpoints = {};
  try { checkpoints = JSON.parse(getAppMeta('cve_year_commits') || '{}'); } catch { checkpoints = {}; }
  if (Object.keys(checkpoints).length === 0 && previousHead && sourceStatuses().some((item) => item.source === 'CVE List' && item.status === 'ready')) {
    const indexedYears = new Set(cveYearCounts().map((item) => String(item.year)));
    if (years.every((year) => indexedYears.has(year))) {
      checkpoints = Object.fromEntries(years.map((year) => [year, previousHead]));
    }
  }
  for (const year of years) {
    state.currentYear = String(year);
    state.currentPhase = 'checking year checkpoint';
    let changes = null;
    const checkpoint = checkpoints[year];
    if (checkpoint) {
      if (checkpoint === head) changes = [];
      else {
        try { changes = await changedCveFiles(repo, checkpoint, head, year); }
        catch { changes = null; }
      }
    }
    if (changes === null) {
      state.currentPhase = 'building year index';
      await importRecordStream('CVE List', cveRecordStream(repo, [year]), { scope: String(year), year });
    } else if (changes.length) {
      await applyChangedCveFiles(repo, year, changes);
    } else {
      state.currentPhase = 'year already current';
      state.currentCount = 0;
    }
    checkpoints[year] = head;
    setAppMeta('cve_year_commits', JSON.stringify(checkpoints));
  }
  state.currentPhase = 'CVE index current';
  state.currentYear = null;
  return indexStats().byKind.find((item) => item.kind === 'cve')?.count || 0;
}

async function syncKev() {
  const payload = await (await fetchResponse(CISA_KEV_URL)).json();
  const records = (payload.vulnerabilities || []).map((item) => ({
    record_id: `kev:${item.cveID}`, kind: 'kev', identifier: item.cveID,
    title: `${item.cveID} · ${item.vulnerabilityName || item.product || 'Known Exploited Vulnerability'}`,
    summary: [item.vendorProject ? `Vendor: ${item.vendorProject}` : '', item.product ? `Product: ${item.product}` : '', item.shortDescription, item.requiredAction ? `Action: ${item.requiredAction}` : '', item.knownRansomwareCampaignUse === 'Known' ? 'Known ransomware campaign use.' : ''].filter(Boolean).join(' '),
    source_name: 'CISA KEV', source_url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    published_at: item.dateAdded || null, severity_score: null, severity_label: null, is_kev: true,
    vendor: item.vendorProject || '', product: item.product || '', technique_id: null
  }));
  return importRecords('CISA KEV', records);
}

async function syncAttack() {
  const payload = await (await fetchResponse(ATTACK_URL, { timeout: 60000 })).json();
  const accepted = new Set(['attack-pattern', 'intrusion-set', 'malware', 'tool', 'campaign', 'course-of-action', 'x-mitre-tactic']);
  const records = (payload.objects || []).filter((item) => accepted.has(item.type) && !item.revoked && !item.x_mitre_deprecated).map((item) => {
    const ref = (item.external_references || []).find((entry) => entry.source_name === 'mitre-attack');
    const id = ref?.external_id || item.id;
    const category = item.type === 'attack-pattern' ? 'techniques' : item.type === 'intrusion-set' ? 'groups' : item.type === 'course-of-action' ? 'mitigations' : item.type === 'x-mitre-tactic' ? 'tactics' : 'software';
    return {
      record_id: `attack:${item.id}`, kind: 'attack', identifier: id, title: item.name || id,
      summary: [item.description || '', item.x_mitre_shortname ? `Short name: ${item.x_mitre_shortname}` : '', item.kill_chain_phases?.map((phase) => phase.phase_name).join(', ') || ''].filter(Boolean).join(' '),
      source_name: 'MITRE ATT&CK', source_url: ref?.url || `https://attack.mitre.org/${category}/${encodeURIComponent(id)}/`,
      published_at: item.modified || item.created || null, severity_score: null, severity_label: null, is_kev: false,
      vendor: '', product: '', technique_id: item.type === 'attack-pattern' ? id : null
    };
  });
  return importRecords('MITRE ATT&CK', records);
}

function htmlText(value) {
  return String(value || '').replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'").replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(Number(code)))
    .replace(/\s+/g, ' ').trim();
}

function parseCertInPage(html, kind, sourceName) {
  const records = [];
  const anchorPattern = /<a\b[^>]*href=["']([^"']*(?:VLCODE|CACODE)=[^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  for (const match of html.matchAll(anchorPattern)) {
    const href = match[1].replace(/&amp;/g, '&');
    const code = new URLSearchParams(href.slice(href.indexOf('?') + 1)).get('VLCODE') || new URLSearchParams(href.slice(href.indexOf('?') + 1)).get('CACODE');
    if (!code || !/^(CIAD|CIVN)-\d{4}-\d+$/.test(code)) continue;
    if (sourceName.includes('Advisories') && !code.startsWith('CIAD-')) continue;
    if (sourceName.includes('Vulnerability Notes') && !code.startsWith('CIVN-')) continue;
    const entryEnd = html.indexOf('</table>', match.index);
    const context = html.slice(match.index + match[0].length, entryEnd < 0 ? match.index + 1800 : entryEnd);
    const contextText = htmlText(context);
    const dateMatch = contextText.match(/\(?([A-Z][a-z]+\s+\d{1,2},\s+\d{4})\)?/);
    const parsedDate = dateMatch ? new Date(dateMatch[1]) : null;
    const date = parsedDate && !Number.isNaN(parsedDate.getTime()) ? parsedDate.toISOString() : null;
    const summary = dateMatch ? contextText.replace(dateMatch[0], '').trim() : contextText;
    records.push({
      record_id: `certin:${code}`, kind, identifier: code,
      title: summary ? `${code} · ${summary.slice(0, 220)}` : code,
      summary: summary || code, source_name: sourceName,
      source_url: new URL(href, 'https://www.cert-in.org.in').href,
      published_at: date, severity_score: null, severity_label: null, is_kev: false,
      vendor: '', product: '', technique_id: null
    });
  }
  return [...new Map(records.map((record) => [record.record_id, record])).values()];
}

async function syncCertInAdvisories() {
  const year = new Date().getUTCFullYear();
  const records = [];
  for (let y = year - 4; y <= year; y += 1) {
    const html = await (await fetchResponse(CERT_IN_ADVISORIES(y), { headers: { accept: 'text/html' } })).text();
    records.push(...parseCertInPage(html, 'certin', 'CERT-In Advisories'));
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return importRecords('CERT-In Advisories', [...new Map(records.map((record) => [record.record_id, record])).values()]);
}

async function syncCertInVulnerabilityNotes() {
  const html = await (await fetchResponse(CERT_IN_HOME, { headers: { accept: 'text/html' } })).text();
  const records = parseCertInPage(html, 'certin', 'CERT-In Vulnerability Notes');
  return importRecords('CERT-In Vulnerability Notes', records);
}

const sources = [
  ['CVE List', syncCveList], ['CISA KEV', syncKev], ['MITRE ATT&CK', syncAttack],
  ['CERT-In Advisories', syncCertInAdvisories], ['CERT-In Vulnerability Notes', syncCertInVulnerabilityNotes]
];

async function runSync() {
  state = { running: true, currentSource: null, currentPhase: 'preparing', currentYear: null, currentCount: 0, startedAt: now(), lastError: null };
  const heartbeat = setInterval(() => {
    updateSyncLease(process.pid, state);
    if (state.currentSource) setSourceStatus(state.currentSource, 'syncing');
  }, 15000);
  heartbeat.unref?.();
  let anySuccess = false;
  try {
    for (const [name, task] of sources) {
      state.currentSource = name;
      state.currentPhase = name === 'CVE List' ? 'preparing CVE repository' : 'downloading source';
      state.currentYear = null;
      state.currentCount = 0;
      updateSyncLease(process.pid, state);
      setSourceStatus(name, 'syncing');
      try {
        const count = await task();
        setSourceStatus(name, 'ready', count);
        anySuccess = true;
      } catch (error) {
        const message = name === 'CVE List'
          ? error.message || 'CVE List sync failed; the previous index was kept.'
          : 'Source unavailable; the last saved index was kept.';
        setSourceStatus(name, 'error', 0, message);
        state.lastError = message;
      }
    }
    if (anySuccess) setLastSync(now());
  } finally {
    clearInterval(heartbeat);
    releaseSyncLease(process.pid);
    state.running = false;
    state.currentSource = null;
    state.currentPhase = null;
    state.currentYear = null;
    state.currentCount = 0;
  }
}

export function startSync() {
  if (state.running) return false;
  if (!acquireSyncLease(process.pid, { currentPhase: 'preparing' })) return false;
  void runSync().catch((error) => {
    state.running = false;
    state.currentSource = null;
    state.currentPhase = null;
    state.currentYear = null;
    state.lastError = 'Index update failed. Existing local data was kept.';
    releaseSyncLease(process.pid);
    console.error('Intel index update failed:', error.message);
  });
  return true;
}

export function syncStatus() {
  const lease = state.running ? null : getSyncLease();
  const current = lease ? {
    running: true, startedAt: lease.startedAt, currentSource: lease.currentSource,
    currentPhase: lease.currentPhase, currentYear: lease.currentYear,
    currentCount: lease.currentCount, lastError: state.lastError
  } : state;
  return { ...current, lastSync: lastSync(), sources: sourceStatuses(), index: indexStats() };
}
