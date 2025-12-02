# DotGit-Privacy

A privacy-focused Firefox WebExtension to detect exposed `.git` repositories and other sensitive files.

## Features

- **Privacy First**: No telemetry, no external endpoints. Scans only happen locally.
- **Per-Origin Opt-In**: Automatic scanning is disabled by default. You must explicitly enable it for each site you trust/want to scan.
- **On-Demand Scanning**: Scan any site manually with a single click.
- **Sensitive File Detection**: Checks for:
    - `.git` repositories
    - `.env` files
    - `.svn` repositories
    - `.hg` (Mercurial) repositories
    - `.DS_Store` (macOS metadata)
    - `security.txt` policies
    - `env` (Python Virtual Environments)
    - `trace` (Trace files)
- **Status Reporting**: Distinguishes between exposed files (200 OK - Green) and forbidden files (403 Forbidden - Red).
- **Notifications**: Alerts you when exposed or forbidden items are found.

## Installation

1.  Clone or download this repository.
2.  Open Firefox and navigate to `about:debugging#/runtime/this-firefox`.
3.  Click **Load Temporary Add-on...**.
4.  Select the `manifest.json` file from the `DotGit-Privacy` directory.

## Developer Checklist

- [ ] Replace `lib/jszip.min.js` with the actual library if you implement full Git dumping.
- [ ] Replace `lib/pako_inflate.min.js` with the actual library if needed.

## Testing Instructions

### 1. Manual Scan
1.  Navigate to a site you want to test (e.g., a local server with a `.git` folder exposed, or `http://localhost:8000`).
2.  Click the extension icon to open the popup.
3.  Click **Scan this site**.
4.  Grant the permission request.
5.  Wait for findings to appear in the popup.

### 2. Per-Site Auto-Scan (The Core Feature)
1.  Navigate to a test site (e.g., `http://localhost:8000`).
2.  Open the popup.
3.  Toggle **Auto-scan this site** to **ON**.
4.  Read the permission prompt and click **Allow**.
5.  **Reload the page** or navigate away and come back.
6.  The extension should automatically scan the site (you might see a notification if enabled).
7.  Open the popup to see the findings without clicking "Scan" again.

### 3. Revoking Permission
1.  Open the popup on the auto-scanned site.
2.  Toggle **Auto-scan this site** to **OFF**.
3.  The site is removed from the auto-scan list.
4.  To fully revoke the permission, go to `about:addons`, click the 3 dots on DotGit-Privacy -> **Manage**, then **Permissions**, and remove the specific site.

### 4. Global Auto-Scan (Optional)
1.  Open the popup and click **Options**.
2.  Enable **Automatic scanning for ALL sites**.
3.  Read the strong warning and confirm twice.
4.  Grant the broad host permission.
5.  Now every site you visit will be scanned automatically.

## Privacy Statement

No telemetry or external endpoints were added to this project. All checks are performed locally by the browser. Findings are stored in `storage.local` and never transmitted.
