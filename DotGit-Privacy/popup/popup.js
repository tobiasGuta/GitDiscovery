const browser = globalThis.browser || globalThis.chrome;

let currentOrigin = null;
let currentTabId = null;

document.addEventListener('DOMContentLoaded', async () => {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return;

  try {
    const url = new URL(tab.url);
    if (!['http:', 'https:'].includes(url.protocol)) {
      document.getElementById('current-origin').textContent = 'Restricted page';
      return;
    }
    currentOrigin = url.origin;
    currentTabId = tab.id;
    document.getElementById('current-origin').textContent = currentOrigin;
  } catch (e) {
    return;
  }

  // Load state
  await updateUI();

  // Event listeners
  document.getElementById('btn-scan').addEventListener('click', handleManualScan);
  document.getElementById('toggle-autoscan').addEventListener('change', handleAutoScanToggle);
  document.getElementById('open-options').addEventListener('click', () => browser.runtime.openOptionsPage());
  document.getElementById('btn-download').addEventListener('click', handleDownload);
  document.getElementById('btn-export').addEventListener('click', handleExport);
  document.getElementById('open-history').addEventListener('click', () => {
    browser.tabs.create({ url: browser.runtime.getURL('history/history.html') });
  });

  // Listen for updates
  browser.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'UPDATE_FINDINGS' && msg.origin === currentOrigin) {
      loadFindings();
    }
  });
});

async function updateUI() {
  const { allowedOrigins } = await browser.storage.local.get('allowedOrigins');
  const isAllowed = allowedOrigins && allowedOrigins.includes(currentOrigin);
  document.getElementById('toggle-autoscan').checked = isAllowed;
  
  await loadFindings();
}

async function loadFindings() {
  const { findings, options } = await browser.storage.local.get(['findings', 'options']);
  const list = document.getElementById('findings-list');
  const area = document.getElementById('findings-area');
  const dlSection = document.getElementById('download-section');
  const dlWarning = document.getElementById('dl-warning');
  
  // Safe DOM clearing — no innerHTML
  list.replaceChildren();
  
  const siteFindings = (findings || []).find(f => f.origin === currentOrigin);
  
  if (siteFindings) {
    area.style.display = 'block';
    if (siteFindings.types.length === 0 && !siteFindings.securitytxt && !siteFindings.opensource) {
      const emptyLi = document.createElement('li');
      emptyLi.textContent = 'No sensitive files found.';
      list.appendChild(emptyLi);
      dlSection.style.display = 'none';
    } else {
      siteFindings.types.forEach(t => {
        const li = document.createElement('li');
        const status = siteFindings.details && siteFindings.details[t];
        
        let displayName = `.${t}`;
        if (t === 'venv') displayName = 'env';
        if (t === 'trace') displayName = 'trace';

        if (status === '403') {
          li.textContent = `Found: ${displayName} (403 Forbidden)`;
          li.style.color = '#d00';
        } else if (status === 'exposed') {
          li.textContent = `Found: ${displayName} (Exposed)`;
          li.style.color = 'green';
        } else {
          li.textContent = `Found: ${displayName}`;
        }
        list.appendChild(li);
      });

      // Safe rendering of security.txt link — no innerHTML
      if (siteFindings.securitytxt) {
        const li = document.createElement('li');
        const textNode = document.createTextNode('Found: ');
        const link = document.createElement('a');
        link.href = siteFindings.securitytxt;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.textContent = 'security.txt';
        li.appendChild(textNode);
        li.appendChild(link);
        list.appendChild(li);
      }
      if (siteFindings.opensource) {
        const li = document.createElement('li');
        li.textContent = `Remote: ${siteFindings.opensource}`;
        list.appendChild(li);
      }

      // Download button logic
      if (siteFindings.types.includes('git')) {
        dlSection.style.display = 'block';
        if (!options || !options.allow_downloads) {
          document.getElementById('btn-download').disabled = true;
          dlWarning.textContent = 'Downloads disabled in Options.';
        } else {
          document.getElementById('btn-download').disabled = false;
          dlWarning.textContent = '';
        }
      }
    }
  } else {
    area.style.display = 'none';
  }
}

async function handleManualScan() {
  // Request permission for this origin
  const granted = await browser.permissions.request({ origins: [currentOrigin + '/*'] });
  if (granted) {
    browser.runtime.sendMessage({ type: 'MANUAL_SCAN', tabId: currentTabId, origin: currentOrigin });
    window.close(); // Optional: close popup or show "Scanning..."
  } else {
    alert('Permission denied. Cannot scan.');
  }
}

async function handleAutoScanToggle(e) {
  const isChecked = e.target.checked;
  
  if (isChecked) {
    // Show warning/explanation
    const confirmScan = confirm(`To auto-scan ${currentOrigin} when you visit it, DotGit-Privacy needs permission to access files on this origin. This will be used only for scanning and not sent anywhere.\n\nProceed?`);
    if (!confirmScan) {
      e.target.checked = false;
      return;
    }

    const granted = await browser.permissions.request({ origins: [currentOrigin + '/*'] });
    if (granted) {
      const { allowedOrigins } = await browser.storage.local.get('allowedOrigins');
      const newOrigins = allowedOrigins || [];
      if (!newOrigins.includes(currentOrigin)) {
        newOrigins.push(currentOrigin);
        await browser.storage.local.set({ allowedOrigins: newOrigins });
      }
    } else {
      e.target.checked = false;
    }
  } else {
    // Revoke
    const { allowedOrigins } = await browser.storage.local.get('allowedOrigins');
    const newOrigins = (allowedOrigins || []).filter(o => o !== currentOrigin);
    await browser.storage.local.set({ allowedOrigins: newOrigins });
    
    // Optional: remove permission
    await browser.permissions.remove({ origins: [currentOrigin + '/*'] });
  }
}

async function handleDownload() {
  const confirmDl = confirm(`Download .git repository from ${currentOrigin}?\n\nThis will attempt to reconstruct the git repository from exposed files.`);
  if (confirmDl) {
    const granted = await browser.permissions.request({ permissions: ['downloads'] });
    if (granted) {
      document.getElementById('btn-download').disabled = true;
      document.getElementById('btn-download').textContent = 'Downloading...';
      browser.runtime.sendMessage({ 
        type: 'DOWNLOAD_REPO', 
        origin: currentOrigin
      });
    }
  }
}

async function handleExport() {
  const { findings } = await browser.storage.local.get('findings');
  if (!findings || findings.length === 0) {
    alert('No findings to export.');
    return;
  }

  const format = document.getElementById('export-format').value;
  let content, filename, mimeType;

  if (format === 'json') {
    content = JSON.stringify(findings, null, 2);
    filename = `dotgit-findings-${Date.now()}.json`;
    mimeType = 'application/json';
  } else {
    // CSV export
    const headers = ['Origin', 'Types', 'Details', 'SecurityTxt', 'OpenSource', 'Timestamp'];
    const rows = findings.map(f => [
      f.origin,
      (f.types || []).join('; '),
      Object.entries(f.details || {}).map(([k,v]) => `${k}=${v}`).join('; '),
      f.securitytxt || '',
      f.opensource || '',
      new Date(f.timestamp).toISOString()
    ]);
    content = [headers.join(','), ...rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(','))].join('\n');
    filename = `dotgit-findings-${Date.now()}.csv`;
    mimeType = 'text/csv';
  }

  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
