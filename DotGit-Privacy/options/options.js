const browser = globalThis.browser || globalThis.chrome;

document.addEventListener('DOMContentLoaded', restoreOptions);
document.getElementById('save').addEventListener('click', saveOptions);
document.getElementById('auto-scan-all').addEventListener('change', handleGlobalScanToggle);

const CHECK_IDS = [
  'git', 'env', 'svn', 'hg', 'ds_store', 'securitytxt', 'venv', 'trace',
  'htaccess', 'htpasswd', 'wp_config_bak', 'phpinfo', 'robots', 'sitemap',
  'dockerenv', 'actuator', 'graphql', 'debug_pages', 'backup_files',
  'ssh_keys', 'crossdomain', 'composer', 'package_json', 'server_status'
];

async function restoreOptions() {
  const { options } = await browser.storage.local.get('options');
  if (!options) return;

  // Restore all check toggles
  for (const id of CHECK_IDS) {
    const el = document.getElementById('check-' + id);
    if (el && options.checks) el.checked = !!options.checks[id];
  }
  
  document.getElementById('notification-new').checked = !!options.notification_new_git;
  document.getElementById('allow-downloads').checked = !!options.allow_downloads;
  document.getElementById('auto-scan-all').checked = !!options.automatic_scanning_all;
  document.getElementById('stealth-mode').checked = !!options.stealth_mode;
  document.getElementById('request-delay').value = options.request_delay || 100;
}

async function saveOptions() {
  const checks = {};
  for (const id of CHECK_IDS) {
    const el = document.getElementById('check-' + id);
    checks[id] = el ? el.checked : false;
  }

  const options = {
    checks,
    notification_new_git: document.getElementById('notification-new').checked,
    allow_downloads: document.getElementById('allow-downloads').checked,
    automatic_scanning_all: document.getElementById('auto-scan-all').checked,
    stealth_mode: document.getElementById('stealth-mode').checked,
    request_delay: parseInt(document.getElementById('request-delay').value, 10) || 100
  };

  await browser.storage.local.set({ options });
  
  const status = document.getElementById('saved-msg');
  status.style.display = 'inline';
  setTimeout(() => {
    status.style.display = 'none';
  }, 1500);
}

async function handleGlobalScanToggle(e) {
  const isChecked = e.target.checked;
  
  if (isChecked) {
    const confirmed = confirm("WARNING: You are about to enable automatic scanning for ALL sites.\n\nThis requires granting the extension permission to access data on all websites. This is a significant privacy change.\n\nAre you sure you want to proceed?");
    
    if (confirmed) {
      const doubleCheck = confirm("Please confirm again: Do you want to allow DotGit-Privacy to scan every website you visit?");
      if (doubleCheck) {
        const granted = await browser.permissions.request({
          origins: ["http://*/*", "https://*/*"]
        });
        if (!granted) {
          e.target.checked = false;
        }
      } else {
        e.target.checked = false;
      }
    } else {
      e.target.checked = false;
    }
  } else {
    // Optionally remove broad permissions
    // browser.permissions.remove({ origins: ["http://*/*", "https://*/*"] });
  }
}
