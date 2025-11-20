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
  
  list.innerHTML = '';
  
  const siteFindings = (findings || []).find(f => f.origin === currentOrigin);
  
  if (siteFindings) {
    area.style.display = 'block';
    if (siteFindings.types.length === 0 && !siteFindings.securitytxt && !siteFindings.opensource) {
      list.innerHTML = '<li>No sensitive files found.</li>';
      dlSection.style.display = 'none';
    } else {
      siteFindings.types.forEach(t => {
        const li = document.createElement('li');
        li.textContent = `Found: .${t}`;
        list.appendChild(li);
      });
      if (siteFindings.securitytxt) {
        const li = document.createElement('li');
        li.innerHTML = `Found: <a href="${siteFindings.securitytxt}" target="_blank">security.txt</a>`;
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
        if (!options.allow_downloads) {
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
  const confirmDl = confirm(`Download .git repository from ${currentOrigin}?`);
  if (confirmDl) {
    // Request download permission if not present (though manifest has it optional)
    const granted = await browser.permissions.request({ permissions: ['downloads'] });
    if (granted) {
      browser.runtime.sendMessage({ 
        type: 'DOWNLOAD_REPO', 
        origin: currentOrigin, 
        url: currentOrigin + '/.git/config' // Placeholder URL
      });
    }
  }
}
