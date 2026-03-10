# DotGit-Privacy

A privacy-focused Firefox WebExtension for bug bounty hunters to detect exposed `.git` repositories, sensitive files, and common misconfigurations.

## Features

- **Privacy First**: No telemetry, no external endpoints. All checks run locally in your browser.
- **Per-Origin Opt-In**: Automatic scanning is disabled by default. Explicitly enable it per-site or globally.
- **On-Demand Scanning**: Scan any site manually with a single click.
- **30+ Sensitive File Checks** with content validation to reduce false positives:
  - **Version Control**: `.git`, `.svn`, `.hg`
  - **Environment / Secrets**: `.env`, `.htpasswd`, SSH keys, Docker detection
  - **Web Server**: `.htaccess`, `server-status`, `server-info`, `phpinfo.php`
  - **Framework-Specific**: WordPress config backups, Spring Boot Actuator, GraphQL, debug pages (elmah, telescope, debugbar)
  - **Data Exposure**: `robots.txt`, `sitemap.xml`, `crossdomain.xml`, `composer.json`, `package.json`
  - **Backup Files**: `backup.zip`, `backup.sql`, `dump.sql`, etc.
  - **Other**: `.DS_Store`, `security.txt` (RFC 9116 validated), `trace`, `venv`
- **Full .git Dumper**: Downloads and reconstructs exposed `.git` repositories as ZIP files (fetches HEAD, refs, objects, pack files).
- **Color-Coded Badge**: Green badge = exposed items count, Orange badge = 403/forbidden items count.
- **Export Findings**: Export all findings as JSON or CSV for reporting.
- **Findings History**: Persistent history page with filtering, sorting, and export.
- **Stealth Mode**: Configurable request delays to avoid triggering WAFs.
- **Content Validation**: All checks validate response bodies (magic bytes, patterns, headers) — not just HTTP status codes — to eliminate soft-404 false positives.

## Security

- No `innerHTML` usage all DOM manipulation uses safe APIs (`textContent`, `createElement`).
- Content Security Policy enforced via manifest.
- Message sender validation prevents spoofed findings from compromised pages.
- Download URLs validated against expected origins.
- Re-injection guard uses `Symbol` (not overridable by page scripts).

## Installation

1. Clone or download this repository.
2. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`.
3. Click **Load Temporary Add-on...**.
4. Select the `manifest.json` file from the `DotGit-Privacy` directory.

## Usage

### Manual Scan
1. Navigate to a target site.
2. Click the extension icon to open the popup.
3. Click **Scan Now** and grant the permission request.
4. Findings appear in the popup with color-coded status.

### Per-Site Auto-Scan
1. Open the popup on a target site.
2. Toggle **Auto-scan this site** to ON.
3. Grant the permission.
4. The site will be scanned automatically on every visit.

### Global Auto-Scan
1. Open **Options** from the popup.
2. Enable **Automatic scanning for ALL sites** (requires double confirmation + broad host permission).

### Downloading Exposed .git
1. Enable **Allow Downloads** in Options.
2. When a `.git` exposure is found, click **Download .git** in the popup.
3. The extension fetches HEAD, config, refs, objects (up to 500), and pack files, then saves as a ZIP.

### Stealth Mode
1. Open **Options**.
2. Enable **Stealth Mode** and set a request delay (e.g., 200ms).
3. Checks will be throttled to avoid WAF detection.

### Exporting Findings
- Use the **Export** dropdown in the popup for current findings.
- Use the **History** page for full historical export with filtering.

<img width="372" height="581" alt="Screenshot 2026-03-10 140049" src="https://github.com/user-attachments/assets/3f7a5b83-1a42-4bed-a2c9-e0aba7ea9069" />

## Required: Install Libraries

The `.git` dumper/download feature requires two third-party libraries. The `lib/` folder contains **placeholder files** that must be replaced with the real libraries before the extension will work fully.

### 1. JSZip (required for .git download as ZIP)

1. Go to https://github.com/Stuk/jszip/releases
2. Download the latest release
3. Copy `dist/jszip.min.js` into `DotGit-Privacy/lib/`, replacing the existing placeholder

### 2. Pako (required for inflating git objects)

1. Go to https://github.com/nicoreed/pako/releases or https://www.npmjs.com/package/pako
2. Download the latest release
3. Copy `dist/pako_inflate.min.js` into `DotGit-Privacy/lib/`, replacing the existing placeholder

**Without these libraries, scanning still works — only the "Download .git" feature will fail.**

## Privacy Statement

No telemetry or external endpoints. All checks are performed locally by the browser. Findings are stored in `storage.local` and never transmitted.
