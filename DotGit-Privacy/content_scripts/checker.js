(function() {
  if (window.hasDotGitChecker) return;
  window.hasDotGitChecker = true;

  const browser = globalThis.browser || globalThis.chrome;

  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'CHECK_SITE') {
      runChecks(message.origin, message.options).then(findings => {
        browser.runtime.sendMessage({
          type: 'FINDINGS',
          origin: message.origin,
          data: findings
        });
      });
    }
  });

  async function fetchWithTimeout(url, timeout = 3000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        cache: 'no-store'
      });
      clearTimeout(id);
      return response;
    } catch (error) {
      clearTimeout(id);
      return null;
    }
  }

  async function runChecks(origin, options) {
    const findings = {
      origin,
      types: [],
      securitytxt: false,
      opensource: false,
      timestamp: Date.now()
    };

    const checks = options.checks || {};

    // Helper to check existence
    const checkUrl = async (path) => {
      const resp = await fetchWithTimeout(origin + path);
      return resp && resp.status === 200;
    };

    // .git check
    if (checks.git) {
      const headResp = await fetchWithTimeout(origin + '/.git/HEAD');
      if (headResp && headResp.status === 200) {
        const text = await headResp.text();
        if (text.trim().startsWith('ref:')) {
          findings.types.push('git');
          // Try to get config for remote
          const configResp = await fetchWithTimeout(origin + '/.git/config');
          if (configResp && configResp.status === 200) {
            const configText = await configResp.text();
            const match = configText.match(/url\s*=\s*(.+)/);
            if (match) {
              findings.opensource = match[1].trim();
            }
          }
        }
      }
    }

    // .env check
    if (checks.env) {
      if (await checkUrl('/.env')) findings.types.push('env');
    }

    // .svn check
    if (checks.svn) {
      if (await checkUrl('/.svn/wc.db')) findings.types.push('svn');
    }

    // .hg check
    if (checks.hg) {
      if (await checkUrl('/.hg/store/00manifest.i')) findings.types.push('hg');
    }

    // .DS_Store check
    if (checks.ds_store) {
      if (await checkUrl('/.DS_Store')) findings.types.push('ds_store');
    }

    // security.txt check
    if (checks.securitytxt) {
      if (await checkUrl('/.well-known/security.txt')) {
        findings.securitytxt = origin + '/.well-known/security.txt';
      } else if (await checkUrl('/security.txt')) {
        findings.securitytxt = origin + '/security.txt';
      }
    }

    return findings;
  }
})();
