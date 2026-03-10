(function() {
  // Secure re-injection guard using Symbol (not overridable by page JS)
  const GUARD = Symbol.for('__dotgit_checker_guard__');
  if (window[GUARD]) return;
  Object.defineProperty(window, GUARD, { value: true, writable: false, configurable: false });

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

  async function fetchWithTimeout(url, timeout = 5000) {
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
    const delay = options.request_delay || 0;
    const stealthMode = options.stealth_mode || false;

    const delayMs = () => {
      if (stealthMode || delay > 0) {
        return new Promise(r => setTimeout(r, delay || 100));
      }
      return Promise.resolve();
    };

    const recordFinding = (type, status) => {
      if (status === 200 || status === 403 || status === 401) {
        if (!findings.types.includes(type)) {
          findings.types.push(type);
        }
        findings.details[type] = status === 200 ? 'exposed' : '403';
      }
    };

    // --- Content Validators ---
    // These reduce false positives by validating response bodies, not just status codes

    function looksLikeErrorPage(text, contentType) {
      if (contentType && contentType.includes('text/html') && text.length > 1000) return true;
      if (/<html|<!doctype/i.test(text.substring(0, 200))) return true;
      return false;
    }

    async function checkWithValidation(path, type, validator) {
      const resp = await fetchWithTimeout(origin + path);
      if (!resp) return;
      if (resp.status === 403 || resp.status === 401) {
        recordFinding(type, 403);
        return;
      }
      if (resp.status === 200) {
        if (validator) {
          try {
            const contentType = resp.headers.get('content-type') || '';
            const body = await resp.text();
            if (validator(body, contentType)) {
              recordFinding(type, 200);
            }
          } catch (e) { /* ignore */ }
        } else {
          recordFinding(type, 200);
        }
      }
    }

    async function checkBinaryWithValidation(path, type, magicBytes) {
      const resp = await fetchWithTimeout(origin + path);
      if (!resp) return;
      if (resp.status === 403 || resp.status === 401) {
        recordFinding(type, 403);
        return;
      }
      if (resp.status === 200) {
        try {
          const buf = await resp.arrayBuffer();
          const arr = new Uint8Array(buf);
          if (magicBytes.every((b, i) => arr[i] === b)) {
            recordFinding(type, 200);
          }
        } catch (e) { /* ignore */ }
      }
    }

    // --- Batch 1: Critical checks (run in parallel) ---
    const batch1 = [];

    // .git check (with deep validation)
    if (checks.git) {
      batch1.push((async () => {
        const headResp = await fetchWithTimeout(origin + '/.git/HEAD');
        if (headResp) {
          if (headResp.status === 200) {
            const text = await headResp.text();
            if (text.trim().startsWith('ref:') || /^[0-9a-f]{40}$/.test(text.trim())) {
              recordFinding('git', 200);
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
      })());
    }

    // .env check — validate KEY=VALUE pattern
    if (checks.env) {
      batch1.push(checkWithValidation('/.env', 'env', (body, ct) => {
        if (looksLikeErrorPage(body, ct)) return false;
        return /^[A-Z_][A-Z0-9_]*\s*=/m.test(body);
      }));
    }

    // .svn check — validate SQLite magic bytes
    if (checks.svn) {
      batch1.push(checkBinaryWithValidation('/.svn/wc.db', 'svn',
        [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65] // "SQLite"
      ));
    }

    // .hg check — mercurial revlog
    if (checks.hg) {
      batch1.push(checkWithValidation('/.hg/store/00manifest.i', 'hg', (body, ct) => {
        if (looksLikeErrorPage(body, ct)) return false;
        return body.length > 0 && !/<html/i.test(body.substring(0, 200));
      }));
    }

    // .DS_Store — validate magic bytes: 0x00 0x00 0x00 0x01 B u d 1
    if (checks.ds_store) {
      batch1.push(checkBinaryWithValidation('/.DS_Store', 'ds_store',
        [0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31]
      ));
    }

    await Promise.all(batch1);
    await delayMs();

    // --- Batch 2: Additional checks (run in parallel) ---
    const batch2 = [];

    // venv check
    if (checks.venv) {
      batch2.push((async () => {
        for (const path of ['/env/', '/venv/']) {
          const resp = await fetchWithTimeout(origin + path);
          if (resp) {
            if (resp.status === 200) {
              const text = await resp.text();
              // A directory listing typically contains "Index of" or links
              if (/index of|<a\s+href/i.test(text)) {
                recordFinding('venv', 200);
                return;
              }
            } else if (resp.status === 403 || resp.status === 401) {
              recordFinding('venv', 403);
              return;
            }
          }
        }
      })());
    }

    // trace check
    if (checks.trace) {
      batch2.push(checkWithValidation('/trace', 'trace', (body, ct) => {
        if (looksLikeErrorPage(body, ct)) return false;
        return body.length > 0;
      }));
    }

    // security.txt check
    if (checks.securitytxt) {
      batch2.push((async () => {
        for (const path of ['/.well-known/security.txt', '/security.txt']) {
          const resp = await fetchWithTimeout(origin + path);
          if (resp && resp.status === 200) {
            const text = await resp.text();
            // RFC 9116 requires Contact: field
            if (/^Contact:/mi.test(text)) {
              findings.securitytxt = origin + path;
              return;
            }
          }
        }
      })());
    }

    // .htaccess
    if (checks.htaccess) {
      batch2.push(checkWithValidation('/.htaccess', 'htaccess', (body, ct) => {
        if (looksLikeErrorPage(body, ct)) return false;
        return /RewriteEngine|Deny|Allow|AuthType|Redirect|Options/i.test(body);
      }));
    }

    // .htpasswd
    if (checks.htpasswd) {
      batch2.push(checkWithValidation('/.htpasswd', 'htpasswd', (body, ct) => {
        if (looksLikeErrorPage(body, ct)) return false;
        // Format: username:hash
        return /^[a-zA-Z0-9_-]+:\S+/m.test(body);
      }));
    }

    await Promise.all(batch2);
    await delayMs();

    // --- Batch 3: Web-framework-specific checks ---
    const batch3 = [];

    // WordPress backup files
    if (checks.wp_config_bak) {
      batch3.push((async () => {
        for (const path of ['/wp-config.php.bak', '/wp-config.php~', '/wp-config.php.old', '/wp-config.php.save']) {
          const resp = await fetchWithTimeout(origin + path);
          if (resp && resp.status === 200) {
            const text = await resp.text();
            if (/DB_NAME|DB_PASSWORD|DB_HOST/i.test(text)) {
              recordFinding('wp_config_bak', 200);
              return;
            }
          } else if (resp && (resp.status === 403 || resp.status === 401)) {
            recordFinding('wp_config_bak', 403);
            return;
          }
        }
      })());
    }

    // phpinfo
    if (checks.phpinfo) {
      batch3.push(checkWithValidation('/phpinfo.php', 'phpinfo', (body, ct) => {
        return /phpinfo\(\)|PHP Version|Configuration File/i.test(body);
      }));
    }

    // robots.txt
    if (checks.robots) {
      batch3.push(checkWithValidation('/robots.txt', 'robots', (body, ct) => {
        return /^(User-agent|Disallow|Allow|Sitemap):/mi.test(body);
      }));
    }

    // sitemap.xml
    if (checks.sitemap) {
      batch3.push(checkWithValidation('/sitemap.xml', 'sitemap', (body, ct) => {
        return /<urlset|<sitemapindex/i.test(body);
      }));
    }

    await Promise.all(batch3);
    await delayMs();

    // --- Batch 4: Infrastructure/DevOps checks ---
    const batch4 = [];

    // Docker
    if (checks.dockerenv) {
      batch4.push((async () => {
        const resp = await fetchWithTimeout(origin + '/.dockerenv');
        if (resp) {
          if (resp.status === 200) recordFinding('dockerenv', 200);
          else if (resp.status === 403 || resp.status === 401) recordFinding('dockerenv', 403);
        }
      })());
    }

    // Spring Boot Actuator
    if (checks.actuator) {
      batch4.push(checkWithValidation('/actuator', 'actuator', (body, ct) => {
        return /"_links"|"self"|"health"|"info"/i.test(body);
      }));
    }

    // GraphQL
    if (checks.graphql) {
      batch4.push((async () => {
        const resp = await fetchWithTimeout(origin + '/graphql');
        if (resp) {
          if (resp.status === 200) {
            const text = await resp.text();
            if (/graphql|"data"|"errors"/i.test(text)) {
              recordFinding('graphql', 200);
            }
          } else if (resp.status === 403 || resp.status === 401) {
            recordFinding('graphql', 403);
          }
        }
      })());
    }

    // Debug/error pages
    if (checks.debug_pages) {
      batch4.push((async () => {
        for (const path of ['/debug', '/elmah.axd', '/_debugbar', '/telescope']) {
          const resp = await fetchWithTimeout(origin + path);
          if (resp && resp.status === 200) {
            const text = await resp.text();
            if (!looksLikeErrorPage(text, '') || /debug|stacktrace|exception|telescope/i.test(text)) {
              recordFinding('debug_pages', 200);
              return;
            }
          } else if (resp && (resp.status === 403 || resp.status === 401)) {
            recordFinding('debug_pages', 403);
            return;
          }
        }
      })());
    }

    // Apache server-status / server-info
    if (checks.server_status) {
      batch4.push((async () => {
        for (const path of ['/server-status', '/server-info']) {
          const resp = await fetchWithTimeout(origin + path);
          if (resp && resp.status === 200) {
            const text = await resp.text();
            if (/Apache Server Status|Server Information/i.test(text)) {
              recordFinding('server_status', 200);
              return;
            }
          } else if (resp && (resp.status === 403 || resp.status === 401)) {
            recordFinding('server_status', 403);
            return;
          }
        }
      })());
    }

    await Promise.all(batch4);
    await delayMs();

    // --- Batch 5: Data exposure checks ---
    const batch5 = [];

    // Backup files
    if (checks.backup_files) {
      batch5.push((async () => {
        for (const path of ['/backup.zip', '/backup.sql', '/db.sql', '/database.sql', '/dump.sql', '/backup.tar.gz']) {
          const resp = await fetchWithTimeout(origin + path);
          if (resp && resp.status === 200) {
            const ct = resp.headers.get('content-type') || '';
            // Must not be HTML (soft 404)
            if (!ct.includes('text/html')) {
              recordFinding('backup_files', 200);
              return;
            }
          } else if (resp && (resp.status === 403 || resp.status === 401)) {
            recordFinding('backup_files', 403);
            return;
          }
        }
      })());
    }

    // SSH keys
    if (checks.ssh_keys) {
      batch5.push(checkWithValidation('/.ssh/id_rsa', 'ssh_keys', (body, ct) => {
        return /BEGIN.*PRIVATE KEY/i.test(body);
      }));
    }

    // crossdomain.xml
    if (checks.crossdomain) {
      batch5.push(checkWithValidation('/crossdomain.xml', 'crossdomain', (body, ct) => {
        return /<cross-domain-policy|<allow-access-from/i.test(body);
      }));
    }

    // composer.json
    if (checks.composer) {
      batch5.push(checkWithValidation('/composer.json', 'composer', (body, ct) => {
        if (looksLikeErrorPage(body, ct)) return false;
        try { const j = JSON.parse(body); return j.require || j.name; } catch { return false; }
      }));
    }

    // package.json
    if (checks.package_json) {
      batch5.push(checkWithValidation('/package.json', 'package_json', (body, ct) => {
        if (looksLikeErrorPage(body, ct)) return false;
        try { const j = JSON.parse(body); return j.dependencies || j.name; } catch { return false; }
      }));
    }

    await Promise.all(batch5);

    return findings;
  }
})();
