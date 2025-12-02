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
      details: {},
      securitytxt: false,
      opensource: false,
      timestamp: Date.now()
    };

    const checks = options.checks || {};

    // Helper to check status
    const checkUrlStatus = async (path) => {
      const resp = await fetchWithTimeout(origin + path);
      return resp ? resp.status : null;
    };

    const recordFinding = (type, status) => {
      if (status === 200 || status === 403 || status === 401) {
        if (!findings.types.includes(type)) {
          findings.types.push(type);
        }
        findings.details[type] = status === 200 ? 'exposed' : '403';
      }
    };

    // .git check
    if (checks.git) {
      const headResp = await fetchWithTimeout(origin + '/.git/HEAD');
      if (headResp) {
        if (headResp.status === 200) {
          const text = await headResp.text();
          if (text.trim().startsWith('ref:')) {
            recordFinding('git', 200);
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
        } else if (headResp.status === 403 || headResp.status === 401) {
          recordFinding('git', 403);
        }
      }
    }

    // .env check
    if (checks.env) {
      recordFinding('env', await checkUrlStatus('/.env'));
    }

    // .svn check
    if (checks.svn) {
      recordFinding('svn', await checkUrlStatus('/.svn/wc.db'));
    }

    // .hg check
    if (checks.hg) {
      recordFinding('hg', await checkUrlStatus('/.hg/store/00manifest.i'));
    }

    // .DS_Store check
    if (checks.ds_store) {
      recordFinding('ds_store', await checkUrlStatus('/.DS_Store'));
    }

    // venv check (checking for 'env' folder as requested)
    if (checks.venv) {
      const venvPaths = ['/env', '/env/'];
      let statusToRecord = null;

      for (const path of venvPaths) {
        const status = await checkUrlStatus(path);
        if (status === 200) {
          statusToRecord = 200;
          break;
        } else if (status === 403 || status === 401) {
          statusToRecord = 403;
        }
      }
      
      if (statusToRecord) {
        recordFinding('venv', statusToRecord);
      }
    }

    // trace check
    if (checks.trace) {
      recordFinding('trace', await checkUrlStatus('/trace'));
    }

    // security.txt check
    if (checks.securitytxt) {
      if ((await checkUrlStatus('/.well-known/security.txt')) === 200) {
        findings.securitytxt = origin + '/.well-known/security.txt';
      } else if ((await checkUrlStatus('/security.txt')) === 200) {
        findings.securitytxt = origin + '/security.txt';
      }
    }

    return findings;
  }
})();
