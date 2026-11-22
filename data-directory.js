import os from 'node:os';
import path from 'node:path';

export function dataDirectory() {
  if (process.env.BHARAT_DATA_DIR) return path.resolve(process.env.BHARAT_DATA_DIR);
  if (process.env.LOCALAPPDATA) return path.join(process.env.LOCALAPPDATA, 'BharatSearch');
  if (process.platform === 'darwin') return path.join(os.homedir(), 'Library', 'Application Support', 'BharatSearch');
  return path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'bharat-search');
}
