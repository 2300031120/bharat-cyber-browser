export const APP_UPDATE_REPOSITORY = '2300031120/bharat-cyber-browser';
export const APP_UPDATE_INTERVAL = '24 hours';

export function shouldStartAppUpdater({ isPackaged, platform, argv = [] }) {
  return Boolean(isPackaged && platform === 'win32' && !argv.includes('--squirrel-firstrun'));
}
