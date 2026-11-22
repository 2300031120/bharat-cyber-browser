# Bharat Cyber Browser

Bharat Cyber Browser is a Windows Chromium desktop app for cybersecurity analysts. It combines everyday website browsing with local search across public cyber-intelligence feeds. It does not crawl or search the general web, route traffic through Tor, or provide anonymity.

## Run from source

Requires Node.js 24.13+ and Git for CVE List synchronization.

```powershell
npm install
npm run desktop
```

The desktop app includes tabs, URL navigation, back/forward/reload, local bookmarks and browsing history, save-to-disk downloads, and private windows. Type a CVE, product, advisory phrase, or ATT&CK ID in the address bar to search the local cyber index; enter a website URL to browse. `Ctrl+L`, `Ctrl+T`, `Ctrl+W`, and `Ctrl+Shift+N` focus the address bar, create a tab, close a tab, and open a private window.

## Make a Windows installer

```powershell
npm run make
```

Electron Forge creates an unsigned Squirrel.Windows installer under `out/make`. Packaged Windows builds check the public GitHub release feed at startup and daily, download available updates, then ask before restarting. Checks contact `update.electronjs.org` and disclose the app version and network address; search queries and local index data are not sent. The current public version is `v0.2.0`. Future updates use stable SemVer GitHub Releases with `RELEASES`, the full `.nupkg`, and the installer from `out/make`; all release assets are public. Draft and prerelease versions are not delivered by the public update service. Windows App Control may still block unsigned installers or updates; the app does not bypass that policy. With no signing certificate, run from source using the commands above or ask your administrator to allow the installer.

## Search index and local data

The index stores CVE List V5 records for the current and previous five calendar years, CISA KEV, MITRE ATT&CK Enterprise, and recent CERT-In advisories and vulnerability notes. CVE triage ranks exact CVE matches first; product searches prioritize known-exploited entries, then severity and recency. Results show source links and explain the indexed exploit and severity signals. An optional glossary explains common terms in Telugu or Hindi while retaining the official English source text. Sync runs independently for each source; a failed source keeps its last successful records. CVE years are indexed newest first, with per-year checkpoints; later syncs update only changed CVE files. The UI shows the phase, year, and processed count, and newly indexed records are searchable during sync with an incomplete-results notice. The initial checkout can still take time and uses disk space. Before CVE sync, the app removes Git lock files only when they are at least 30 minutes old and no Git process is active; recent locks or an inconclusive process check leave the files untouched.

Search, bookmarks, and normal browsing history stay on this device under `%LOCALAPPDATA%\BharatSearch`. No account, cloud sync, paid feed, or search-query history is used. Browser history contains visited website URLs only and can be cleared from the History menu. Private windows do not save cookies, history, or bookmarks; files downloaded from a private window are still saved to the location you choose.

Passive asset lookups remain optional and require an explicit consent checkbox. Domains are sent to crt.sh, RDAP, and Google Public DNS; IP addresses are sent to RDAP. These services can see the submitted target. The app does not scan the target.

## Security and maintenance

Remote pages run in sandboxed Chromium views without Node.js integration or app preload APIs. Website permissions are denied by default. Keep Electron updated to receive Chromium security fixes; Electron's security guidance recommends isolation, sandboxing, limited navigation, and current releases: [Electron security](https://www.electronjs.org/docs/latest/tutorial/security).

### Public data sources

- [CVE List V5](https://github.com/CVEProject/cvelistV5)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK](https://attack.mitre.org/resources/attack-data-and-tools/)
- [CERT-In](https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
