module.exports = {
  packagerConfig: {
    asar: { unpack: '{package.json,desktop/server-worker.js,server.js,intel-store.js,intel-sync.js,asset-osint.js,data-directory.js}' },
    executableName: 'BharatCyberBrowser',
    appBundleId: 'in.bharatcyber.browser'
  },
  rebuildConfig: {},
  makers: [{
    name: '@electron-forge/maker-squirrel',
    config: {
      name: 'BharatCyberBrowser',
      authors: 'Bharat Cyber Search',
      description: 'A local-first Chromium browser with cybersecurity intelligence search'
    }
  }]
};
