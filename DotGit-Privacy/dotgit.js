const browser = globalThis.browser || globalThis.chrome;

// In-memory state — keyed by origin to prevent race conditions
const processingOrigins = new Map(); // origin -> timestamp

// Default options including all check types
const DEFAULT_OPTIONS = {
  allow_downloads: false,
  automatic_scanning_all: false,
  notification_new_git: true,
  stealth_mode: false,
  request_delay: 100,
  checks: {
    git: true,
    env: true,
    svn: true,
    hg: true,
    ds_store: true,
    securitytxt: true,
    venv: true,
    trace: true,
    htaccess: true,
    htpasswd: true,
    wp_config_bak: true,
    phpinfo: true,
    robots: true,
    sitemap: true,
    dockerenv: true,
    actuator: true,
    graphql: true,
    debug_pages: true,
    backup_files: true,
    ssh_keys: true,
    crossdomain: true,
    composer: true,
    package_json: true,
    server_status: true
  }
};

// Initialize storage on install/startup
browser.runtime.onInstalled.addListener(async () => {
  const { allowedOrigins, options } = await browser.storage.local.get(['allowedOrigins', 'options']);
  if (!allowedOrigins) {
    await browser.storage.local.set({ allowedOrigins: [] });
  }
  if (!options) {
    await browser.storage.local.set({ options: DEFAULT_OPTIONS });
  } else {
    // Merge any new check keys that are missing from older installs
    const merged = { ...DEFAULT_OPTIONS, ...options, checks: { ...DEFAULT_OPTIONS.checks, ...options.checks } };
    await browser.storage.local.set({ options: merged });
  }
});

// Automatic scanning trigger
browser.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    await checkAndInject(tab);
  }
});

// Message handler with sender validation
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'MANUAL_SCAN') {
    // Only accept from popup (no sender.tab means it's from extension UI)
    if (sender.tab) return false;
    browser.tabs.get(message.tabId).then(tab => checkAndInject(tab, true));
    return false;
  } else if (message.type === 'FINDINGS') {
    // Validate sender: must come from a content script in a tab
    if (!sender.tab || !sender.tab.id) {
      console.warn('Rejected FINDINGS from non-tab sender.');
      return false;
    }
    // Validate the origin matches the sender's tab origin
    try {
      const senderOrigin = new URL(sender.tab.url || sender.url).origin;
      if (senderOrigin !== message.origin) {
        console.warn(`Origin mismatch: sender=${senderOrigin}, claimed=${message.origin}`);
        return false;
      }
    } catch (e) {
      return false;
    }
    handleFindings(message.origin, message.data, sender.tab.id);
  } else if (message.type === 'DOWNLOAD_REPO') {
    // Only accept from popup (no sender.tab)
    if (sender.tab) return false;
    // Validate origin format
    try {
      const url = new URL(message.origin);
      if (!['http:', 'https:'].includes(url.protocol)) return false;
    } catch (e) {
      return false;
    }
    performDownload(message.origin);
  }
  return false;
});

async function checkAndInject(tab, isManual = false) {
  let origin;
  try {
    const url = new URL(tab.url);
    if (!['http:', 'https:'].includes(url.protocol)) return;
    origin = url.origin;
  } catch (e) {
    return;
  }

  // Race condition fix: use Map with timestamps, reject if recently started
  const existing = processingOrigins.get(origin);
  if (existing && (Date.now() - existing) < 10000) return;

  const { allowedOrigins, options } = await browser.storage.local.get(['allowedOrigins', 'options']);
  
  const isAllowedOrigin = allowedOrigins && allowedOrigins.includes(origin);
  const isGlobalScan = options && options.automatic_scanning_all;

  if (!isManual && !isAllowedOrigin && !isGlobalScan) {
    return;
  }

  const hasPermission = await browser.permissions.contains({ origins: [origin + '/*'] });
  if (!hasPermission) {
    if (isManual) {
      console.warn(`Missing permission for ${origin} during manual scan.`);
    }
    return;
  }

  processingOrigins.set(origin, Date.now());
  try {
    await browser.scripting.executeScript({
      target: { tabId: tab.id },
      files: ['content_scripts/checker.js']
    });

    await browser.tabs.sendMessage(tab.id, {
      type: 'CHECK_SITE',
      origin: origin,
      options: options
    });
  } catch (err) {
    console.error(`Scan failed for ${origin}:`, err);
  } finally {
    setTimeout(() => {
      processingOrigins.delete(origin);
    }, 10000);
  }
}

async function handleFindings(origin, data, tabId) {
  const { findings, options } = await browser.storage.local.get(['findings', 'options']);
  const findingsList = findings || [];
  
  // Remove old findings for this origin to update with new ones
  const filtered = findingsList.filter(f => f.origin !== origin);
  
  const hasFindings = data.types.length > 0 || data.securitytxt || data.opensource;
  
  if (hasFindings) {
    filtered.push({
      origin,
      ...data,
      timestamp: Date.now()
    });
    
    await browser.storage.local.set({ findings: filtered });

    // Append to history (persistent, append-only log)
    const { history } = await browser.storage.local.get('history');
    const historyList = history || [];
    historyList.push({
      origin,
      ...data,
      timestamp: Date.now()
    });
    // Cap history at 1000 entries
    if (historyList.length > 1000) historyList.splice(0, historyList.length - 1000);
    await browser.storage.local.set({ history: historyList });

    let hasExposed = false;
    let has403 = false;
    const exposedItems = [];
    const forbiddenItems = [];

    data.types.forEach(t => {
      const status = data.details && data.details[t];
      let name = t;
      if (t === 'venv') name = 'env';
      if (t === 'trace') name = 'trace';

      if (status === 'exposed') {
        hasExposed = true;
        exposedItems.push(name);
      }
      if (status === '403') {
        has403 = true;
        forbiddenItems.push(name);
      }
    });

    if (data.securitytxt) { hasExposed = true; exposedItems.push('security.txt'); }
    if (data.opensource) { hasExposed = true; exposedItems.push('git config'); }

    // Set badge icon with color-coded status
    if (tabId) {
      if (hasExposed) {
        browser.action.setBadgeBackgroundColor({ color: '#2e7d32', tabId });
        browser.action.setBadgeText({ text: String(exposedItems.length), tabId });
      } else if (has403) {
        browser.action.setBadgeBackgroundColor({ color: '#e65100', tabId });
        browser.action.setBadgeText({ text: String(forbiddenItems.length), tabId });
      } else {
        browser.action.setBadgeText({ text: '', tabId });
      }
    }

    // Trigger Notifications
    if (options && options.notification_new_git !== false) {
      if (hasExposed) {
        browser.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon.svg',
          title: 'DotGit-Privacy: EXPOSED (200)',
          message: `Found exposed items on ${origin}: ${exposedItems.join(', ')}`
        });
      } else if (has403) {
        browser.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon.svg',
          title: 'DotGit-Privacy: Forbidden (403)',
          message: `Found forbidden items on ${origin}: ${forbiddenItems.join(', ')}`
        });
      }
    }
    
    // Notify popup to refresh if open
    browser.runtime.sendMessage({ type: 'UPDATE_FINDINGS', origin }).catch(() => {});
  } else {
    // No findings — clear badge
    if (tabId) {
      browser.action.setBadgeText({ text: '', tabId });
    }
  }
}

async function performDownload(origin) {
  const { options } = await browser.storage.local.get('options');
  
  if (!options || !options.allow_downloads) {
    console.warn('Download attempted but allow_downloads is false.');
    return;
  }

  // Validate origin — must be http/https
  try {
    const url = new URL(origin);
    if (!['http:', 'https:'].includes(url.protocol)) {
      console.warn('Invalid origin protocol for download.');
      return;
    }
  } catch (e) {
    console.warn('Invalid origin for download.');
    return;
  }

  const hasDownloadPerm = await browser.permissions.contains({ permissions: ['downloads'] });
  if (!hasDownloadPerm) {
    console.warn('Missing downloads permission.');
    return;
  }

  const baseUrl = origin + '/.git';
  const collectedFiles = {};
  const objectHashes = new Set();
  const delay = options.request_delay || 50;
  const delayFetch = () => new Promise(r => setTimeout(r, delay));

  // Helper to fetch a git file
  async function fetchGitFile(url) {
    try {
      const resp = await fetch(url, { cache: 'no-store' });
      if (resp.status === 200) return resp;
      return null;
    } catch (e) {
      return null;
    }
  }

  // Phase 1: Fetch core git files
  const coreFiles = [
    '/HEAD', '/config', '/description', '/packed-refs',
    '/info/refs', '/info/exclude',
    '/refs/heads/master', '/refs/heads/main',
    '/refs/remotes/origin/HEAD'
  ];

  for (const file of coreFiles) {
    const resp = await fetchGitFile(baseUrl + file);
    if (resp) {
      const text = await resp.text();
      collectedFiles['.git' + file] = text;

      // Extract 40-char hex hashes
      for (const match of text.matchAll(/\b([0-9a-f]{40})\b/g)) {
        objectHashes.add(match[1]);
      }

      // Follow ref: pointers
      for (const match of text.matchAll(/ref:\s*(.+)/g)) {
        const refPath = match[1].trim();
        const refResp = await fetchGitFile(baseUrl + '/' + refPath);
        if (refResp) {
          const refText = await refResp.text();
          collectedFiles['.git/' + refPath] = refText;
          const refHash = refText.trim();
          if (/^[0-9a-f]{40}$/.test(refHash)) objectHashes.add(refHash);
        }
      }
    }
    if (options.stealth_mode) await delayFetch();
  }

  // Phase 2: Parse packed-refs for more hashes
  if (collectedFiles['.git/packed-refs']) {
    for (const line of collectedFiles['.git/packed-refs'].split('\n')) {
      const match = line.match(/^([0-9a-f]{40})\s+(.+)/);
      if (match) objectHashes.add(match[1]);
    }
  }

  // Phase 3: Recursively fetch git objects (commit -> tree -> blob)
  const fetchedObjects = new Set();
  const objectQueue = [...objectHashes];
  let fetchCount = 0;
  const MAX_OBJECTS = 500;

  while (objectQueue.length > 0 && fetchCount < MAX_OBJECTS) {
    const hash = objectQueue.shift();
    if (fetchedObjects.has(hash)) continue;
    fetchedObjects.add(hash);

    const objPath = `/objects/${hash.substring(0, 2)}/${hash.substring(2)}`;
    const resp = await fetchGitFile(baseUrl + objPath);
    if (resp) {
      const arrayBuf = await resp.arrayBuffer();
      collectedFiles['.git' + objPath] = new Uint8Array(arrayBuf);
      fetchCount++;

      // Try to inflate with pako and extract more hashes
      try {
        const inflated = pako.inflate(new Uint8Array(arrayBuf));
        const text = new TextDecoder('utf-8', { fatal: false }).decode(inflated);
        
        // Extract text-form hashes (parent, tree lines in commits)
        for (const m of text.matchAll(/\b([0-9a-f]{40})\b/g)) {
          if (!fetchedObjects.has(m[1])) objectQueue.push(m[1]);
        }

        // Parse tree objects: binary hashes stored as 20 bytes after null byte
        if (text.startsWith('tree ')) {
          const raw = inflated;
          let i = raw.indexOf(0) + 1;
          while (i < raw.length) {
            while (i < raw.length && raw[i] !== 0) i++;
            i++;
            if (i + 20 <= raw.length) {
              const hashHex = Array.from(raw.slice(i, i + 20)).map(b => b.toString(16).padStart(2, '0')).join('');
              if (!fetchedObjects.has(hashHex)) objectQueue.push(hashHex);
              i += 20;
            } else {
              break;
            }
          }
        }
      } catch (e) {
        // Not all objects are parseable as text
      }
    }

    if (options.stealth_mode || delay > 0) await delayFetch();
  }

  // Phase 4: Try to fetch pack files
  const packsResp = await fetchGitFile(baseUrl + '/objects/info/packs');
  if (packsResp) {
    const packsText = await packsResp.text();
    collectedFiles['.git/objects/info/packs'] = packsText;
    for (const match of packsText.matchAll(/P\s+(pack-[0-9a-f]+\.pack)/g)) {
      const packName = match[1];
      const packResp = await fetchGitFile(baseUrl + '/objects/pack/' + packName);
      if (packResp) {
        collectedFiles['.git/objects/pack/' + packName] = new Uint8Array(await packResp.arrayBuffer());
      }
      const idxName = packName.replace('.pack', '.idx');
      const idxResp = await fetchGitFile(baseUrl + '/objects/pack/' + idxName);
      if (idxResp) {
        collectedFiles['.git/objects/pack/' + idxName] = new Uint8Array(await idxResp.arrayBuffer());
      }
    }
  }

  // Phase 5: Build ZIP using JSZip
  const zip = new JSZip();
  for (const [path, content] of Object.entries(collectedFiles)) {
    zip.file(path, content);
  }

  const zipBlob = await zip.generateAsync({ type: 'blob' });
  const safeName = origin.replace(/[^a-z0-9.-]/gi, '_');
  const blobUrl = URL.createObjectURL(zipBlob);

  browser.downloads.download({
    url: blobUrl,
    filename: `dotgit_dump_${safeName}_${Date.now()}.zip`,
    saveAs: true
  });
}
