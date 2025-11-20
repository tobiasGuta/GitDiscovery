const browser = globalThis.browser || globalThis.chrome;

document.addEventListener('DOMContentLoaded', restoreOptions);
document.getElementById('save').addEventListener('click', saveOptions);
document.getElementById('auto-scan-all').addEventListener('change', handleGlobalScanToggle);

async function restoreOptions() {
  const { options } = await browser.storage.local.get('options');
  if (!options) return;

  document.getElementById('check-git').checked = options.checks.git;
  document.getElementById('check-env').checked = options.checks.env;
  document.getElementById('check-svn').checked = options.checks.svn;
  document.getElementById('check-hg').checked = options.checks.hg;
  document.getElementById('check-ds_store').checked = options.checks.ds_store;
  document.getElementById('check-securitytxt').checked = options.checks.securitytxt;
  
  document.getElementById('notification-new').checked = options.notification_new_git;
  document.getElementById('allow-downloads').checked = options.allow_downloads;
  document.getElementById('auto-scan-all').checked = options.automatic_scanning_all;
}

async function saveOptions() {
  const options = {
    checks: {
      git: document.getElementById('check-git').checked,
      env: document.getElementById('check-env').checked,
      svn: document.getElementById('check-svn').checked,
      hg: document.getElementById('check-hg').checked,
      ds_store: document.getElementById('check-ds_store').checked,
      securitytxt: document.getElementById('check-securitytxt').checked
    },
    notification_new_git: document.getElementById('notification-new').checked,
    allow_downloads: document.getElementById('allow-downloads').checked,
    automatic_scanning_all: document.getElementById('auto-scan-all').checked
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
