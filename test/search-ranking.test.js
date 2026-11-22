import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const testDataDirectory = mkdtempSync(path.join(os.tmpdir(), 'bharat-cyber-search-'));
process.env.BHARAT_DATA_DIR = testDataDirectory;
const store = await import('../intel-store.js');
const sync = await import('../intel-sync.js');

const records = [
  {
    record_id: 'kev:CVE-2024-1000', kind: 'kev', identifier: 'CVE-2024-1000',
    title: 'CVE-2024-1000 · Acme Widget', summary: 'Known exploited vulnerability. Vendor: Acme. Products: Acme Widget.',
    source_name: 'CISA KEV', source_url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    published_at: '2024-02-01', severity_score: null, severity_label: null, is_kev: true,
    vendor: 'Acme', product: 'Acme Widget', technique_id: null
  },
  {
    record_id: 'cve:CVE-2024-1000', kind: 'cve', identifier: 'CVE-2024-1000',
    title: 'CVE-2024-1000 · Acme Widget', summary: 'Vendor: Acme. Products: Acme Widget.',
    source_name: 'CVE List', source_url: 'https://www.cve.org/CVERecord?id=CVE-2024-1000',
    published_at: '2024-03-01', severity_score: 8.8, severity_label: 'High', is_kev: false,
    vendor: 'Acme', product: 'Acme Widget', technique_id: null
  },
  {
    record_id: 'cve:CVE-2024-2000', kind: 'cve', identifier: 'CVE-2024-2000',
    title: 'CVE-2024-2000 · Acme Widget', summary: 'Vendor: Acme. Products: Acme Widget.',
    source_name: 'CVE List', source_url: 'https://www.cve.org/CVERecord?id=CVE-2024-2000',
    published_at: '2025-03-01', severity_score: 9.8, severity_label: 'Critical', is_kev: false,
    vendor: 'Acme', product: 'Acme Widget', technique_id: null
  },
  {
    record_id: 'cve:CVE-2025-0500', kind: 'cve', identifier: 'CVE-2025-0500',
    title: 'CVE-2025-0500 · Acme Widget', summary: 'Vendor: Acme. Products: Acme Widget.',
    source_name: 'CVE List', source_url: 'https://www.cve.org/CVERecord?id=CVE-2025-0500',
    published_at: '2025-01-01', severity_score: 6.5, severity_label: 'Medium', is_kev: false,
    vendor: 'Acme', product: 'Acme Widget', technique_id: null
  }
];

store.beginSourceImport();
store.importSourceBatch(records);
store.finishSourceImport('CVE List');

test('product searches put known-exploited records ahead of severity and recency', () => {
  const { results } = store.searchIntel({ query: 'Acme Widget', limit: 10 });
  assert.deepEqual(results.map((item) => item.id), [
    'kev:CVE-2024-1000', 'cve:CVE-2024-2000', 'cve:CVE-2024-1000', 'cve:CVE-2025-0500'
  ]);
  assert.equal(results[0].sourceUrl, 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog');
});

test('exact CVE searches keep exact records first and show KEV evidence first', () => {
  const { results } = store.searchIntel({ query: 'CVE-2024-1000', limit: 10 });
  assert.deepEqual(results.slice(0, 2).map((item) => item.id), [
    'kev:CVE-2024-1000', 'cve:CVE-2024-1000'
  ]);
  assert.equal(results[0].kev, 1);
});

test('newly indexed records are searchable while a source import is still in progress', () => {
  store.beginSourceImport();
  store.importSourceBatch([{
    ...records[1], record_id: 'cve:CVE-2026-9999', identifier: 'CVE-2026-9999',
    title: 'CVE-2026-9999 · Acme Widget', source_url: 'https://www.cve.org/CVERecord?id=CVE-2026-9999'
  }]);
  const partial = store.searchIntel({ query: 'CVE-2026-9999', limit: 10 });
  const previous = store.searchIntel({ query: 'CVE-2024-1000', limit: 10 });
  assert.equal(partial.results[0]?.identifier, 'CVE-2026-9999');
  assert.ok(previous.results.some((item) => item.id === 'cve:CVE-2024-1000'));
});

test('year-scoped rebuild removes stale records only from that year', () => {
  store.beginSourceImport('2025');
  store.importSourceBatch([{
    ...records[3], record_id: 'cve:CVE-2025-0501', identifier: 'CVE-2025-0501',
    title: 'CVE-2025-0501 · Acme Widget', source_url: 'https://www.cve.org/CVERecord?id=CVE-2025-0501'
  }], '2025');
  store.finishSourceImport('CVE List', '2025', 2025);
  assert.equal(store.searchIntel({ query: 'CVE-2025-0500' }).total, 0);
  assert.equal(store.searchIntel({ query: 'CVE-2025-0501' }).total, 1);
  assert.equal(store.searchIntel({ query: 'CVE-2024-1000' }).total, 2);
});

test('CVE indexing order starts with the newest year and covers six years', () => {
  assert.deepEqual(sync.cveYearsToIndex(2026), ['2026', '2025', '2024', '2023', '2022', '2021']);
});

test('Git diff parsing accepts only CVE JSON changes inside the requested year', () => {
  const output = [
    'M', 'cves/2025/01/CVE-2025-1234.json',
    'D', 'cves/2025/02/CVE-2025-4321.json',
    'A', 'cves/2024/01/CVE-2024-9999.json',
    'R100', 'cves/2025/01/not-a-cve.txt',
    ''
  ].join('\0');
  const parsed = sync.parseCveDiff(output, path.join(testDataDirectory, 'repo'), '2025');
  assert.deepEqual(parsed.map(({ status, file }) => [status, path.basename(file)]), [
    ['M', 'CVE-2025-1234.json'], ['D', 'CVE-2025-4321.json']
  ]);
});

test('sync leases block overlapping workers and recover stale runs', () => {
  const staleTime = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  assert.equal(store.acquireSyncLease(1111, { currentSource: 'CVE List' }), true);
  assert.equal(store.acquireSyncLease(2222), false);
  store.updateSyncLease(1111, { currentSource: 'CVE List' }, staleTime);
  store.setSourceStatus('CVE List', 'syncing');
  assert.equal(store.getSyncLease(), null);
  assert.equal(store.sourceStatuses().find((source) => source.source === 'CVE List').status, 'error');
  assert.equal(store.acquireSyncLease(2222), true);
  store.releaseSyncLease(2222);
});

after(() => {
  store.db.close();
  rmSync(testDataDirectory, { recursive: true, force: true });
});
