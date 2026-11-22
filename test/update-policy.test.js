import test from 'node:test';
import assert from 'node:assert/strict';
import { APP_UPDATE_INTERVAL, APP_UPDATE_REPOSITORY, shouldStartAppUpdater } from '../desktop/update-policy.js';

test('automatic updates are enabled for installed Windows builds only', () => {
  assert.equal(shouldStartAppUpdater({ isPackaged: true, platform: 'win32', argv: [] }), true);
  assert.equal(shouldStartAppUpdater({ isPackaged: false, platform: 'win32', argv: [] }), false);
  assert.equal(shouldStartAppUpdater({ isPackaged: true, platform: 'linux', argv: [] }), false);
  assert.equal(shouldStartAppUpdater({ isPackaged: true, platform: 'win32', argv: ['--squirrel-firstrun'] }), false);
});

test('update checks use the public project feed once per day', () => {
  assert.equal(APP_UPDATE_REPOSITORY, '2300031120/bharat-cyber-browser');
  assert.equal(APP_UPDATE_INTERVAL, '24 hours');
});
