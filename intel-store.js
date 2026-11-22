import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { dataDirectory } from './data-directory.js';

export { dataDirectory };

const directory = dataDirectory();
mkdirSync(directory, { recursive: true });
export const db = new DatabaseSync(path.join(directory, 'intel.db'), { timeout: 5000 });
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;
  CREATE TABLE IF NOT EXISTS intel_records (
    record_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    identifier TEXT,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    source_name TEXT NOT NULL,
    source_url TEXT NOT NULL,
    published_at TEXT,
    severity_score REAL,
    severity_label TEXT,
    is_kev INTEGER NOT NULL DEFAULT 0,
    vendor TEXT,
    product TEXT,
    technique_id TEXT,
    updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS intel_records_kind ON intel_records(kind);
  CREATE INDEX IF NOT EXISTS intel_records_severity ON intel_records(severity_label);
  CREATE INDEX IF NOT EXISTS intel_records_kev ON intel_records(is_kev);
  CREATE TABLE IF NOT EXISTS source_status (
    source_name TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT,
    error TEXT
  );
  CREATE TABLE IF NOT EXISTS app_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS sync_lease (
    id INTEGER PRIMARY KEY CHECK(id=1), owner_pid INTEGER NOT NULL, started_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL, current_source TEXT, current_phase TEXT, current_year TEXT,
    current_count INTEGER NOT NULL DEFAULT 0
  );
  CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
    record_id UNINDEXED, title, summary, identifier, vendor, product, technique_id
  );
  CREATE TEMP TABLE IF NOT EXISTS staged_record_ids (record_id TEXT NOT NULL, scope TEXT NOT NULL DEFAULT '', PRIMARY KEY(record_id, scope));
`);

const upsertRecord = db.prepare(`
  INSERT INTO intel_records (
    record_id, kind, identifier, title, summary, source_name, source_url, published_at,
    severity_score, severity_label, is_kev, vendor, product, technique_id, updated_at
  ) VALUES (
    $record_id, $kind, $identifier, $title, $summary, $source_name, $source_url, $published_at,
    $severity_score, $severity_label, $is_kev, $vendor, $product, $technique_id, $updated_at
  ) ON CONFLICT(record_id) DO UPDATE SET
    kind=excluded.kind, identifier=excluded.identifier, title=excluded.title, summary=excluded.summary,
    source_name=excluded.source_name, source_url=excluded.source_url, published_at=excluded.published_at,
    severity_score=excluded.severity_score, severity_label=excluded.severity_label, is_kev=excluded.is_kev,
    vendor=excluded.vendor, product=excluded.product, technique_id=excluded.technique_id, updated_at=excluded.updated_at
`);
const deleteFts = db.prepare('DELETE FROM records_fts WHERE record_id = ?');
const stageRecord = db.prepare('INSERT OR IGNORE INTO staged_record_ids(record_id,scope) VALUES (?,?)');
const insertFts = db.prepare(`INSERT INTO records_fts (record_id,title,summary,identifier,vendor,product,technique_id)
  VALUES ($record_id,$title,$summary,$identifier,$vendor,$product,$technique_id)`);

export function beginSourceImport(scope = '') {
  db.prepare('DELETE FROM staged_record_ids WHERE scope=?').run(String(scope));
}

export function importSourceBatch(records, scope = '', stage = true) {
  if (!records.length) return;
  db.exec('BEGIN IMMEDIATE');
  try {
    for (const record of records) {
      const normalized = {
        record_id: String(record.record_id), kind: String(record.kind), identifier: record.identifier || null,
        title: String(record.title || record.identifier || 'Untitled'), summary: String(record.summary || ''),
        source_name: String(record.source_name), source_url: String(record.source_url || ''),
        published_at: record.published_at || null, severity_score: Number.isFinite(record.severity_score) ? record.severity_score : null,
        severity_label: record.severity_label || null, is_kev: record.is_kev ? 1 : 0,
        vendor: record.vendor || null, product: record.product || null, technique_id: record.technique_id || null,
        updated_at: new Date().toISOString()
      };
      upsertRecord.run(normalized);
      deleteFts.run(normalized.record_id);
      insertFts.run({
        record_id: normalized.record_id, title: normalized.title, summary: normalized.summary,
        identifier: normalized.identifier, vendor: normalized.vendor, product: normalized.product,
        technique_id: normalized.technique_id
      });
      if (stage) stageRecord.run(normalized.record_id, String(scope));
    }
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

export function finishSourceImport(sourceName, scope = '', year = null) {
  const scopeValue = String(scope);
  const count = db.prepare('SELECT COUNT(*) AS count FROM staged_record_ids WHERE scope=?').get(scopeValue).count;
  if (!count) throw new Error('The source returned no records; keeping the previous index.');
  db.exec('BEGIN IMMEDIATE');
  try {
    const yearFilter = year == null ? '' : ' AND substr(identifier,5,4)=?';
    db.prepare(`DELETE FROM records_fts WHERE record_id IN (
      SELECT record_id FROM intel_records WHERE source_name = ?${yearFilter}
        AND record_id NOT IN (SELECT record_id FROM staged_record_ids WHERE scope=?)
    )`).run(...(year == null ? [sourceName, scopeValue] : [sourceName, String(year), scopeValue]));
    db.prepare(`DELETE FROM intel_records WHERE source_name = ?${yearFilter}
      AND record_id NOT IN (SELECT record_id FROM staged_record_ids WHERE scope=?)`)
      .run(...(year == null ? [sourceName, scopeValue] : [sourceName, String(year), scopeValue]));
    db.prepare('DELETE FROM staged_record_ids WHERE scope=?').run(scopeValue);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  return count;
}

export function setSourceStatus(sourceName, status, recordCount = 0, error = null) {
  db.prepare(`INSERT INTO source_status(source_name,status,record_count,updated_at,error)
    VALUES (?,?,?,?,?) ON CONFLICT(source_name) DO UPDATE SET status=excluded.status,
    record_count=CASE WHEN excluded.record_count > 0 THEN excluded.record_count ELSE source_status.record_count END,
    updated_at=excluded.updated_at,error=excluded.error`).run(
    sourceName, status, recordCount, new Date().toISOString(), error ? String(error).slice(0, 300) : null
  );
}

export function sourceStatuses() {
  return db.prepare('SELECT source_name AS source, status, record_count AS records, updated_at AS updatedAt, error FROM source_status ORDER BY source_name').all();
}

export function lastSync() {
  return db.prepare("SELECT value FROM app_meta WHERE key='last_sync'").get()?.value || null;
}

export function setLastSync(value) {
  db.prepare("INSERT INTO app_meta(key,value) VALUES('last_sync',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(value);
}

export function getAppMeta(key) {
  return db.prepare('SELECT value FROM app_meta WHERE key=?').get(String(key))?.value ?? null;
}

export function setAppMeta(key, value) {
  db.prepare('INSERT INTO app_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
    .run(String(key), String(value));
}

const SYNC_LEASE_TIMEOUT_MS = 5 * 60 * 1000;

export function acquireSyncLease(ownerPid, progress = {}, timestamp = new Date().toISOString()) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const current = db.prepare('SELECT owner_pid AS ownerPid, started_at AS startedAt, heartbeat_at AS heartbeatAt FROM sync_lease WHERE id=1').get();
    if (current && Date.now() - Date.parse(current.heartbeatAt) < SYNC_LEASE_TIMEOUT_MS) {
      db.exec('COMMIT');
      return false;
    }
    if (current) {
      db.prepare(`UPDATE source_status SET status='error',updated_at=?,error='A previous sync stopped before it completed; retry to resume.' WHERE status='syncing'`).run(timestamp);
      db.prepare('DELETE FROM sync_lease WHERE id=1').run();
    }
    db.prepare(`INSERT INTO sync_lease(id,owner_pid,started_at,heartbeat_at,current_source,current_phase,current_year,current_count)
      VALUES(1,?,?,?,?,?,?,?)`).run(ownerPid, timestamp, timestamp, progress.currentSource || null, progress.currentPhase || null,
      progress.currentYear || null, Number(progress.currentCount || 0));
    db.exec('COMMIT');
    return true;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

export function updateSyncLease(ownerPid, progress = {}, timestamp = new Date().toISOString()) {
  db.prepare(`UPDATE sync_lease SET heartbeat_at=?,current_source=?,current_phase=?,current_year=?,current_count=?
    WHERE id=1 AND owner_pid=?`).run(timestamp, progress.currentSource || null, progress.currentPhase || null,
    progress.currentYear || null, Number(progress.currentCount || 0), ownerPid);
}

export function releaseSyncLease(ownerPid) {
  db.prepare('DELETE FROM sync_lease WHERE id=1 AND owner_pid=?').run(ownerPid);
}

export function getSyncLease(timestamp = new Date().toISOString()) {
  let current = db.prepare(`SELECT owner_pid AS ownerPid,started_at AS startedAt,heartbeat_at AS heartbeatAt,
    current_source AS currentSource,current_phase AS currentPhase,current_year AS currentYear,current_count AS currentCount
    FROM sync_lease WHERE id=1`).get();
  if (!current) return null;
  if (Date.parse(timestamp) - Date.parse(current.heartbeatAt) <= SYNC_LEASE_TIMEOUT_MS) return current;
  db.exec('BEGIN IMMEDIATE');
  try {
    current = db.prepare('SELECT heartbeat_at AS heartbeatAt FROM sync_lease WHERE id=1').get();
    if (current && Date.parse(timestamp) - Date.parse(current.heartbeatAt) > SYNC_LEASE_TIMEOUT_MS) {
      db.prepare(`UPDATE source_status SET status='error',updated_at=?,error='A previous sync stopped before it completed; retry to resume.' WHERE status='syncing'`).run(timestamp);
      db.prepare('DELETE FROM sync_lease WHERE id=1').run();
      db.exec('COMMIT');
      return null;
    }
    db.exec('COMMIT');
    return db.prepare(`SELECT owner_pid AS ownerPid,started_at AS startedAt,heartbeat_at AS heartbeatAt,
      current_source AS currentSource,current_phase AS currentPhase,current_year AS currentYear,current_count AS currentCount
      FROM sync_lease WHERE id=1`).get() || null;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

export function removeIntelRecord(recordId) {
  removeIntelRecords([recordId]);
}

export function removeIntelRecords(recordIds) {
  if (!recordIds.length) return;
  db.exec('BEGIN IMMEDIATE');
  try {
    const removeRecord = db.prepare('DELETE FROM intel_records WHERE record_id=?');
    for (const recordId of recordIds) {
      deleteFts.run(String(recordId));
      removeRecord.run(String(recordId));
    }
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

export function searchIntel({ query, kind, severity, kev, limit = 20, offset = 0 }) {
  const terms = query.match(/[\p{L}\p{N}]+/gu) || [];
  if (!terms.length) return { results: [], total: 0 };
  const match = terms.map((term) => `"${term.replace(/"/g, '""')}"*`).join(' AND ');
  const exactCve = /^CVE-\d{4}-\d{4,}$/i.test(query.trim()) ? query.trim() : '';
  const filters = ['records_fts MATCH ?'];
  const params = [match];
  if (kind && kind !== 'all') { filters.push('r.kind = ?'); params.push(kind); }
  if (kev) filters.push('r.is_kev = 1');
  if (severity) {
    const ranges = { critical: [9, 10], high: [7, 9], medium: [4, 7], low: [0, 4] };
    if (ranges[severity]) {
      const [min, max] = ranges[severity];
      filters.push('r.severity_score >= ? AND r.severity_score < ?');
      params.push(min, max);
    }
  }
  const where = filters.join(' AND ');
  const total = db.prepare(`SELECT COUNT(*) AS count FROM records_fts JOIN intel_records r USING(record_id) WHERE ${where}`).get(...params).count;
  const results = db.prepare(`SELECT r.record_id AS id,r.kind,r.identifier,r.title,r.summary,r.source_name AS source,
    r.source_url AS sourceUrl,r.published_at AS publishedAt,r.severity_score AS severityScore,
    r.severity_label AS severity,r.is_kev AS kev,r.vendor,r.product,r.technique_id AS techniqueId
    FROM records_fts JOIN intel_records r USING(record_id) WHERE ${where}
    ORDER BY CASE WHEN r.identifier = ? COLLATE NOCASE THEN 0 ELSE 1 END,
      r.is_kev DESC, r.severity_score DESC, r.published_at DESC, bm25(records_fts)
    LIMIT ? OFFSET ?`)
    .all(...params, exactCve, limit, offset);
  return { results, total };
}

export function indexStats() {
  const byKind = db.prepare('SELECT kind,COUNT(*) AS count FROM intel_records GROUP BY kind ORDER BY kind').all();
  const total = db.prepare('SELECT COUNT(*) AS count FROM intel_records').get().count;
  return { total, byKind };
}

export function cveYearCounts() {
  return db.prepare(`SELECT substr(identifier,5,4) AS year,COUNT(*) AS records
    FROM intel_records WHERE source_name='CVE List' AND identifier GLOB 'CVE-[0-9][0-9][0-9][0-9]-*'
    GROUP BY substr(identifier,5,4)`).all();
}
