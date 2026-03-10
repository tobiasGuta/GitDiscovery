const browser = globalThis.browser || globalThis.chrome;

let allHistory = [];
let sortField = 'timestamp';
let sortDir = -1; // -1 = descending

document.addEventListener('DOMContentLoaded', async () => {
  const { history } = await browser.storage.local.get('history');
  allHistory = history || [];
  render();

  document.getElementById('filter').addEventListener('input', render);
  document.getElementById('status-filter').addEventListener('change', render);
  document.getElementById('btn-export-json').addEventListener('click', exportJSON);
  document.getElementById('btn-export-csv').addEventListener('click', exportCSV);
  document.getElementById('btn-clear').addEventListener('click', clearHistory);

  document.querySelectorAll('th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const field = th.dataset.sort;
      if (sortField === field) {
        sortDir *= -1;
      } else {
        sortField = field;
        sortDir = -1;
      }
      render();
    });
  });
});

function render() {
  const filter = document.getElementById('filter').value.toLowerCase();
  const statusFilter = document.getElementById('status-filter').value;
  const tbody = document.getElementById('history-body');
  const emptyMsg = document.getElementById('empty-msg');

  let filtered = allHistory.filter(entry => {
    if (filter && !entry.origin.toLowerCase().includes(filter)) return false;
    if (statusFilter === 'exposed') {
      return entry.types.some(t => entry.details && entry.details[t] === 'exposed');
    }
    if (statusFilter === '403') {
      return entry.types.some(t => entry.details && entry.details[t] === '403');
    }
    return true;
  });

  filtered.sort((a, b) => {
    let va = a[sortField];
    let vb = b[sortField];
    if (sortField === 'types') {
      va = (a.types || []).join(',');
      vb = (b.types || []).join(',');
    }
    if (va < vb) return -1 * sortDir;
    if (va > vb) return 1 * sortDir;
    return 0;
  });

  // Clear table safely
  tbody.replaceChildren();

  if (filtered.length === 0) {
    emptyMsg.style.display = 'block';
    return;
  }
  emptyMsg.style.display = 'none';

  for (const entry of filtered) {
    const tr = document.createElement('tr');

    const tdOrigin = document.createElement('td');
    tdOrigin.textContent = entry.origin;
    tr.appendChild(tdOrigin);

    const tdTypes = document.createElement('td');
    (entry.types || []).forEach(t => {
      const span = document.createElement('span');
      const status = entry.details && entry.details[t];
      span.textContent = t;
      if (status === 'exposed') span.className = 'exposed';
      else if (status === '403') span.className = 'forbidden';
      tdTypes.appendChild(span);
      tdTypes.appendChild(document.createTextNode(', '));
    });
    if (entry.securitytxt) {
      const span = document.createElement('span');
      span.textContent = 'security.txt';
      span.className = 'exposed';
      tdTypes.appendChild(span);
    }
    // Remove trailing comma
    if (tdTypes.lastChild && tdTypes.lastChild.nodeType === 3) {
      tdTypes.removeChild(tdTypes.lastChild);
    }
    tr.appendChild(tdTypes);

    const tdDate = document.createElement('td');
    tdDate.textContent = new Date(entry.timestamp).toLocaleString();
    tr.appendChild(tdDate);

    tbody.appendChild(tr);
  }
}

function exportJSON() {
  const content = JSON.stringify(allHistory, null, 2);
  downloadFile(content, `dotgit-history-${Date.now()}.json`, 'application/json');
}

function exportCSV() {
  const headers = ['Origin', 'Types', 'Details', 'SecurityTxt', 'OpenSource', 'Timestamp'];
  const rows = allHistory.map(f => [
    f.origin,
    (f.types || []).join('; '),
    Object.entries(f.details || {}).map(([k,v]) => `${k}=${v}`).join('; '),
    f.securitytxt || '',
    f.opensource || '',
    new Date(f.timestamp).toISOString()
  ]);
  const content = [headers.join(','), ...rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(','))].join('\n');
  downloadFile(content, `dotgit-history-${Date.now()}.csv`, 'text/csv');
}

function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function clearHistory() {
  if (confirm('Clear all findings history? This cannot be undone.')) {
    allHistory = [];
    await browser.storage.local.set({ history: [] });
    render();
  }
}
