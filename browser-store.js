import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { dataDirectory } from './data-directory.js';

const directory = dataDirectory();
mkdirSync(directory, { recursive: true });
const db = new DatabaseSync(path.join(directory, 'browser-profile.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;
  CREATE TABLE IF NOT EXISTS bookmarks (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL,
    title TEXT NOT NULL,
    visited_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS history_visited ON history(visited_at DESC);
`);

const listBookmarksQuery = db.prepare('SELECT id,url,title,created_at AS createdAt FROM bookmarks ORDER BY title COLLATE NOCASE LIMIT 500');
const listHistoryQuery = db.prepare('SELECT id,url,title,visited_at AS visitedAt FROM history ORDER BY visited_at DESC LIMIT 500');

export function listBookmarks() { return listBookmarksQuery.all(); }
export function addBookmark(url, title) {
  db.prepare(`INSERT INTO bookmarks(url,title,created_at) VALUES(?,?,?)
    ON CONFLICT(url) DO UPDATE SET title=excluded.title`).run(url, title, new Date().toISOString());
  return listBookmarks();
}
export function removeBookmark(id) {
  db.prepare('DELETE FROM bookmarks WHERE id=?').run(Number(id));
  return listBookmarks();
}
export function hasBookmark(url) {
  return Boolean(db.prepare('SELECT 1 FROM bookmarks WHERE url=?').get(url));
}
export function addHistory(url, title) {
  db.prepare('INSERT INTO history(url,title,visited_at) VALUES(?,?,?)').run(url, title, new Date().toISOString());
  db.exec('DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY visited_at DESC LIMIT 5000)');
  return listHistoryQuery.all();
}
export function listHistory() { return listHistoryQuery.all(); }
export function clearHistory() { db.exec('DELETE FROM history'); }
