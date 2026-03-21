/* ===== CVG Monitoring Dashboard - Client JS ===== */

(function () {
  'use strict';

  // State
  let currentView = 'overview';
  let refreshInterval = null;
  let countdown = 30;
  let countdownInterval = null;
  let statsData = null;

  // --- Navigation ---
  document.querySelectorAll('.nav-item[data-view]').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      switchView(item.dataset.view);
    });
  });

  function switchView(view) {
    currentView = view;
    document.querySelectorAll('.nav-item[data-view]').forEach(n => n.classList.remove('active'));
    document.querySelector(`.nav-item[data-view="${view}"]`).classList.add('active');
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(`view-${view}`).classList.add('active');
    document.getElementById('view-title').textContent = {
      overview: 'Overview',
      requests: 'Verification Requests',
      queue: 'Retry Queue',
      audit: 'Audit Log',
      test: 'Test Console',
    }[view];
    loadViewData(view);
  }

  // --- Auto-refresh ---
  document.getElementById('btn-refresh').addEventListener('click', () => {
    loadViewData(currentView);
    resetCountdown();
  });

  function startAutoRefresh() {
    clearInterval(refreshInterval);
    clearInterval(countdownInterval);
    countdown = 30;
    countdownInterval = setInterval(() => {
      countdown--;
      document.getElementById('countdown').textContent = countdown;
      if (countdown <= 0) {
        loadViewData(currentView);
        countdown = 30;
      }
    }, 1000);
  }

  function resetCountdown() {
    countdown = 30;
    document.getElementById('countdown').textContent = countdown;
  }

  // --- Data Loading ---
  async function fetchJson(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async function loadViewData(view) {
    try {
      // Always refresh health status
      updateHealthStatus();

      switch (view) {
        case 'overview': await loadOverview(); break;
        case 'requests': await loadRequests(); break;
        case 'queue': await loadQueue(); break;
        case 'audit': await loadAudit(); break;
        case 'test': initTestConsole(); break;
      }
    } catch (err) {
      console.error('Failed to load data:', err);
    }
  }

  async function updateHealthStatus() {
    try {
      const health = await fetchJson('/api/v1/health');
      const badge = document.getElementById('ivs-status-badge');
      const isUp = health.components.ivs === 'ok';
      badge.className = `ivs-status ${isUp ? 'available' : 'unavailable'}`;
      badge.querySelector('.status-text').textContent = `IVS: ${isUp ? 'Available' : 'Unavailable'}`;
    } catch (e) { /* ignore */ }
  }

  // --- Overview View ---
  async function loadOverview() {
    const data = await fetchJson('/api/v1/admin/stats');
    statsData = data;
    const el = document.getElementById('view-overview');

    const statusMap = {};
    (data.byStatus || []).forEach(s => statusMap[s.status] = s.count);

    const verified = statusMap['verified'] || 0;
    const failed = statusMap['failed'] || 0;
    const queued = statusMap['queued'] || 0;
    const pending = statusMap['processing'] || 0;

    el.innerHTML = `
      <div class="stats-grid">
        <div class="stat-card accent">
          <div class="stat-label">Total Requests</div>
          <div class="stat-value">${data.overview.total_requests}</div>
          <div class="stat-sub">All time</div>
        </div>
        <div class="stat-card success">
          <div class="stat-label">Verified</div>
          <div class="stat-value">${verified}</div>
          <div class="stat-sub">${data.overview.total_requests ? ((verified / data.overview.total_requests) * 100).toFixed(1) : 0}% success rate</div>
        </div>
        <div class="stat-card info">
          <div class="stat-label">Last 24h</div>
          <div class="stat-value">${data.overview.last_24h}</div>
          <div class="stat-sub">${data.overview.last_hour} in last hour</div>
        </div>
        <div class="stat-card warning">
          <div class="stat-label">In Queue</div>
          <div class="stat-value">${data.queue.pending}</div>
          <div class="stat-sub">${data.queue.total} total queued</div>
        </div>
        <div class="stat-card danger">
          <div class="stat-label">Failed</div>
          <div class="stat-value">${failed}</div>
          <div class="stat-sub">Requires attention</div>
        </div>
        <div class="stat-card purple">
          <div class="stat-label">Audit Events</div>
          <div class="stat-value">${data.audit.total}</div>
          <div class="stat-sub">${data.audit.last24h} in last 24h</div>
        </div>
      </div>

      <div class="grid-2">
        <div>
          <div class="section-title">Request Volume (24h)</div>
          <div class="chart-container">
            ${renderBarChart(data.hourlyVolume)}
          </div>
        </div>
        <div>
          <div class="section-title">Breakdown</div>
          <div class="donut-grid">
            ${renderStatusBreakdown(data.byStatus)}
            ${renderTypeBreakdown(data.byType)}
          </div>
        </div>
      </div>

      <div class="section-title">Recent Requests</div>
      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Correlation ID</th>
              <th>Type</th>
              <th>Masked Value</th>
              <th>Status</th>
              <th>Assujetti</th>
              <th>OneBox</th>
              <th>Sig Verified</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            ${data.recentRequests.map(r => `
              <tr>
                <td class="mono">${r.correlation_id}</td>
                <td><span class="badge badge-info">${r.identifier_type}</span></td>
                <td class="mono">${r.masked_value_preview || '-'}</td>
                <td>${statusBadge(r.status)}</td>
                <td>${r.requesting_assujetti_id}</td>
                <td class="mono">${r.onebox_id}</td>
                <td>${r.ivs_signature_verified ? '<span class="badge badge-success">Yes</span>' : '<span class="badge badge-muted">-</span>'}</td>
                <td>${formatTime(r.created_at)}</td>
              </tr>
            `).join('')}
            ${data.recentRequests.length === 0 ? '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:30px">No requests yet. Use the Test Console to send your first verification request.</td></tr>' : ''}
          </tbody>
        </table>
      </div>
    `;
  }

  // --- Requests View ---
  async function loadRequests() {
    const data = await fetchJson('/api/v1/admin/requests?limit=100');
    const el = document.getElementById('view-requests');

    el.innerHTML = `
      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Correlation ID</th>
              <th>Audit Ref</th>
              <th>Type</th>
              <th>Masked Value</th>
              <th>Status</th>
              <th>Assujetti</th>
              <th>OneBox</th>
              <th>Purpose</th>
              <th>Created</th>
              <th>Completed</th>
            </tr>
          </thead>
          <tbody>
            ${data.items.map(r => `
              <tr>
                <td class="mono">${r.correlation_id}</td>
                <td class="mono" style="font-size:11px">${r.gateway_audit_ref}</td>
                <td><span class="badge badge-info">${r.identifier_type}</span></td>
                <td class="mono">${r.masked_value_preview || '-'}</td>
                <td>${statusBadge(r.status)}</td>
                <td>${r.requesting_assujetti_id}</td>
                <td class="mono">${r.onebox_id}</td>
                <td>${r.purpose || '-'}</td>
                <td>${formatTime(r.created_at)}</td>
                <td>${r.completed_at ? formatTime(r.completed_at) : '-'}</td>
              </tr>
            `).join('')}
            ${data.items.length === 0 ? '<tr><td colspan="10" style="text-align:center;color:var(--text-muted);padding:30px">No verification requests found</td></tr>' : ''}
          </tbody>
        </table>
      </div>
    `;
  }

  // --- Queue View ---
  async function loadQueue() {
    const data = await fetchJson('/api/v1/admin/verification-queue');
    const el = document.getElementById('view-queue');

    el.innerHTML = `
      <div class="stats-grid">
        <div class="stat-card warning">
          <div class="stat-label">Pending Retries</div>
          <div class="stat-value">${data.stats.pending}</div>
        </div>
        <div class="stat-card accent">
          <div class="stat-label">Total in Queue</div>
          <div class="stat-value">${data.stats.total}</div>
        </div>
        ${data.stats.byStatus.map(s => `
          <div class="stat-card">
            <div class="stat-label">${s.status}</div>
            <div class="stat-value">${s.count}</div>
          </div>
        `).join('')}
      </div>
      <div class="btn-row" style="margin-bottom:20px">
        <button class="btn-sm btn-accent" onclick="triggerRetry()">Trigger Manual Retry</button>
        <button class="btn-sm btn-danger-sm" onclick="toggleIvs()">Toggle IVS Availability</button>
      </div>
      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Correlation ID</th>
              <th>Type</th>
              <th>Assujetti</th>
              <th>Status</th>
              <th>Retries</th>
              <th>Next Retry</th>
              <th>Expires</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            ${data.items.map(q => `
              <tr>
                <td class="mono">${q.correlation_id}</td>
                <td><span class="badge badge-info">${q.identifier_type || '-'}</span></td>
                <td>${q.requesting_assujetti_id || '-'}</td>
                <td>${statusBadge(q.status)}</td>
                <td>${q.retry_count}</td>
                <td>${q.next_retry_at ? formatTime(q.next_retry_at) : '-'}</td>
                <td>${formatTime(q.expires_at)}</td>
                <td>${formatTime(q.created_at)}</td>
              </tr>
            `).join('')}
            ${data.items.length === 0 ? '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:30px">Queue is empty</td></tr>' : ''}
          </tbody>
        </table>
      </div>
    `;
  }

  // --- Audit View ---
  async function loadAudit() {
    const data = await fetchJson('/api/v1/admin/audit?limit=200');
    const el = document.getElementById('view-audit');

    el.innerHTML = `
      <div class="table-container">
        <div class="event-stream">
          ${data.events.map(e => `
            <div class="event-item">
              <span class="event-time">${formatTime(e.created_at)}</span>
              <span class="event-type ${auditEventColor(e.event_type)}">${e.event_type}</span>
              <span class="event-correlation">${e.correlation_id || '-'}</span>
              <span class="event-detail">${summarizeDetails(e.details_json)}</span>
            </div>
          `).join('')}
          ${data.events.length === 0 ? '<div style="text-align:center;color:var(--text-muted);padding:30px">No audit events yet</div>' : ''}
        </div>
      </div>
    `;
  }

  // --- Test Console ---
  let testConsoleInit = false;

  function initTestConsole() {
    if (testConsoleInit) return;
    testConsoleInit = true;

    const el = document.getElementById('view-test');
    el.innerHTML = `
      <div class="test-console">
        <div class="console-panel">
          <div class="console-panel-header">
            <span>Request</span>
            <select id="test-preset" class="btn-ghost" style="font-size:11px;padding:4px 8px">
              <option value="niu-bgfi">NIU Verification (BGFI)</option>
              <option value="passport-bgfi">Passport Verification (BGFI)</option>
              <option value="niu-unknown">NIU Not Found</option>
              <option value="niu-queue">NIU with Queue (IVS down)</option>
              <option value="niu-invalid">Invalid NIU Format</option>
            </select>
          </div>
          <div class="console-panel-body">
            <div class="btn-row" style="margin-bottom:12px">
              <span style="font-size:12px;color:var(--text-muted)">OneBox:</span>
              <select id="test-onebox" style="padding:4px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-size:12px">
                <option value="OBX-BGFI-01|dev-key-bgfi-01">OBX-BGFI-01</option>
                <option value="OBX-UBA-01|dev-key-uba-01">OBX-UBA-01</option>
                <option value="OBX-TEST-01|dev-key-test-01">OBX-TEST-01</option>
              </select>
            </div>
            <textarea id="test-request" class="code-input">${JSON.stringify(getPreset('niu-bgfi'), null, 2)}</textarea>
            <div class="btn-row">
              <button class="btn-sm btn-accent" onclick="sendTestRequest()">Send Request</button>
              <button class="btn-sm btn-ghost" onclick="checkRequestStatus()">Check Status</button>
            </div>
          </div>
        </div>
        <div class="console-panel">
          <div class="console-panel-header">
            <span>Response</span>
            <span id="test-status" style="font-size:11px;color:var(--text-muted)"></span>
          </div>
          <div class="console-panel-body">
            <pre id="test-response" class="code-output">// Response will appear here after sending a request</pre>
          </div>
        </div>
      </div>
    `;

    document.getElementById('test-preset').addEventListener('change', (e) => {
      document.getElementById('test-request').value = JSON.stringify(getPreset(e.target.value), null, 2);
    });
  }

  function getPreset(name) {
    const presets = {
      'niu-bgfi': {
        verification_request_id: 'vr-test-niu-bgfi-001',
        identifier: { identifier_type: 'NIU', raw_value: '1234567890123', issuer_country: 'CG' },
        request_context: { requesting_assujetti_id: 'BGFI', requesting_assujetti_name: 'BGFI Congo', onebox_id: 'OBX-BGFI-01', local_request_ref: 'REQ-2026-000771', purpose: 'kyc_verification' },
        person_context: { token: 'pdit:cg:artf:52cee71d-637b-462a-95a3-2f7ec9f844db' },
        options: { queue_if_ivs_unavailable: true, allow_protection_without_registry: false }
      },
      'passport-bgfi': {
        verification_request_id: 'vr-test-passport-bgfi-001',
        identifier: { identifier_type: 'PASSPORT', raw_value: 'CG1234567', issuer_country: 'CG' },
        request_context: { requesting_assujetti_id: 'BGFI', requesting_assujetti_name: 'BGFI Congo', onebox_id: 'OBX-BGFI-01', local_request_ref: 'REQ-2026-000772', purpose: 'kyc_verification' },
        options: { queue_if_ivs_unavailable: true }
      },
      'niu-unknown': {
        verification_request_id: 'vr-test-niu-unknown-001',
        identifier: { identifier_type: 'NIU', raw_value: '0000000000000', issuer_country: 'CG' },
        request_context: { requesting_assujetti_id: 'BGFI', requesting_assujetti_name: 'BGFI Congo', onebox_id: 'OBX-BGFI-01', local_request_ref: 'REQ-2026-000773', purpose: 'kyc_verification' },
        options: { queue_if_ivs_unavailable: false }
      },
      'niu-queue': {
        verification_request_id: 'vr-test-niu-queue-001',
        identifier: { identifier_type: 'NIU', raw_value: '1234567890123', issuer_country: 'CG' },
        request_context: { requesting_assujetti_id: 'BGFI', requesting_assujetti_name: 'BGFI Congo', onebox_id: 'OBX-BGFI-01', local_request_ref: 'REQ-2026-000774', purpose: 'kyc_verification' },
        options: { queue_if_ivs_unavailable: true }
      },
      'niu-invalid': {
        verification_request_id: 'vr-test-niu-invalid-001',
        identifier: { identifier_type: 'NIU', raw_value: '123', issuer_country: 'CG' },
        request_context: { requesting_assujetti_id: 'BGFI', requesting_assujetti_name: 'BGFI Congo', onebox_id: 'OBX-BGFI-01', local_request_ref: 'REQ-2026-000775', purpose: 'kyc_verification' },
        options: {}
      },
    };
    return presets[name] || presets['niu-bgfi'];
  }

  // Global functions called from onclick
  window.sendTestRequest = async function () {
    const textarea = document.getElementById('test-request');
    const output = document.getElementById('test-response');
    const statusEl = document.getElementById('test-status');
    const [oneboxId, apiKey] = document.getElementById('test-onebox').value.split('|');

    try {
      const body = JSON.parse(textarea.value);
      statusEl.textContent = 'Sending...';
      output.textContent = '// Sending request...';

      const res = await fetch('/api/v1/verification/identifiers', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Api-Key': apiKey,
          'X-OneBox-Id': oneboxId,
        },
        body: JSON.stringify(body),
      });

      const data = await res.json();
      output.textContent = JSON.stringify(data, null, 2);
      statusEl.textContent = `${res.status} ${res.statusText}`;

      // Also refresh overview if visible
      if (currentView === 'overview') loadOverview();
      showToast(res.ok ? 'Request sent successfully' : `Error: ${data.error_code || res.status}`, res.ok ? 'success' : 'error');
    } catch (err) {
      output.textContent = `Error: ${err.message}`;
      statusEl.textContent = 'Error';
      showToast('Failed to send request', 'error');
    }
  };

  window.checkRequestStatus = async function () {
    const output = document.getElementById('test-response');
    const statusEl = document.getElementById('test-status');

    // Try to get correlation_id from last response
    let corrId;
    try {
      const lastRes = JSON.parse(output.textContent);
      corrId = lastRes.correlation_id;
    } catch (e) { /* ignore */ }

    if (!corrId) {
      const input = prompt('Enter correlation_id to check:');
      if (!input) return;
      corrId = input;
    }

    const [oneboxId, apiKey] = document.getElementById('test-onebox').value.split('|');

    try {
      statusEl.textContent = 'Checking...';
      const res = await fetch(`/api/v1/verification/requests/${corrId}`, {
        headers: { 'X-Api-Key': apiKey, 'X-OneBox-Id': oneboxId },
      });
      const data = await res.json();
      output.textContent = JSON.stringify(data, null, 2);
      statusEl.textContent = `${res.status} ${res.statusText}`;
    } catch (err) {
      output.textContent = `Error: ${err.message}`;
      statusEl.textContent = 'Error';
    }
  };

  window.triggerRetry = async function () {
    try {
      await fetch('/api/v1/admin/verification-queue/retry', { method: 'POST' });
      showToast('Queue retry triggered', 'success');
      loadQueue();
    } catch (e) {
      showToast('Failed to trigger retry', 'error');
    }
  };

  window.toggleIvs = async function () {
    try {
      const res = await fetch('/api/v1/admin/ivs/toggle', { method: 'POST' });
      const data = await res.json();
      showToast(`IVS is now ${data.ivs_available ? 'Available' : 'Unavailable'}`, data.ivs_available ? 'success' : 'error');
      updateHealthStatus();
      loadQueue();
    } catch (e) {
      showToast('Failed to toggle IVS', 'error');
    }
  };

  // --- Helpers ---
  function statusBadge(status) {
    const map = {
      verified: 'badge-success', success: 'badge-success', succeeded: 'badge-success',
      failed: 'badge-danger', error: 'badge-danger', expired: 'badge-danger',
      invalid: 'badge-danger', signature_failed: 'badge-danger',
      queued: 'badge-warning', retrying: 'badge-warning', pending: 'badge-warning',
      processing: 'badge-info', received: 'badge-info',
      not_found: 'badge-muted', protected_only: 'badge-purple', cancelled: 'badge-muted',
    };
    return `<span class="badge ${map[status] || 'badge-muted'}">${status}</span>`;
  }

  function auditEventColor(type) {
    if (type.includes('SUCCEEDED') || type.includes('VERIFIED') || type.includes('AUTHENTICATED')) return 'badge-success';
    if (type.includes('FAILED') || type.includes('EXPIRED') || type.includes('REJECTED')) return 'badge-danger';
    if (type.includes('QUEUED') || type.includes('RETRIED')) return 'badge-warning';
    return '';
  }

  function formatTime(ts) {
    if (!ts) return '-';
    try {
      const d = new Date(ts.endsWith('Z') ? ts : ts + 'Z');
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        + ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch (e) {
      return ts;
    }
  }

  function summarizeDetails(json) {
    if (!json) return '';
    try {
      const d = JSON.parse(json);
      return Object.entries(d).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(', ');
    } catch (e) {
      return json;
    }
  }

  function renderBarChart(hourlyData) {
    if (!hourlyData || hourlyData.length === 0) {
      return '<div style="text-align:center;color:var(--text-muted);padding:40px 0">No data for the last 24 hours</div>';
    }
    const max = Math.max(...hourlyData.map(d => d.count), 1);
    const bars = hourlyData.map(d => {
      const height = Math.max((d.count / max) * 100, 2);
      const label = d.hour.split('T')[1].replace(':00:00', 'h');
      return `<div class="chart-bar" style="height:${height}%"><div class="chart-tooltip">${label}: ${d.count}</div></div>`;
    }).join('');
    const labels = hourlyData.map(d => `<span>${d.hour.split('T')[1].replace(':00:00', '')}</span>`).join('');
    return `<div class="chart-bar-group">${bars}</div><div class="chart-labels">${labels}</div>`;
  }

  function renderStatusBreakdown(byStatus) {
    if (!byStatus || byStatus.length === 0) return '<div class="donut-card"><h4>By Status</h4><div style="color:var(--text-muted);font-size:12px">No data</div></div>';
    const colors = { verified: '#22c55e', failed: '#ef4444', queued: '#f59e0b', processing: '#3b82f6', not_found: '#6b7280', error: '#ef4444', protected_only: '#a855f7' };
    const total = byStatus.reduce((a, b) => a + b.count, 0) || 1;
    const legendItems = byStatus.map(s => `<div class="donut-legend-item"><span class="legend-dot" style="background:${colors[s.status] || '#6b7280'}"></span>${s.status}: ${s.count}</div>`).join('');
    return `<div class="donut-card"><h4>By Status</h4><div class="donut-legend">${legendItems}</div></div>`;
  }

  function renderTypeBreakdown(byType) {
    if (!byType || byType.length === 0) return '<div class="donut-card"><h4>By Type</h4><div style="color:var(--text-muted);font-size:12px">No data</div></div>';
    const colors = { NIU: '#6366f1', PASSPORT: '#8b5cf6', NID: '#ec4899', DRIVER_LICENSE: '#f59e0b' };
    const legendItems = byType.map(t => `<div class="donut-legend-item"><span class="legend-dot" style="background:${colors[t.identifier_type] || '#6b7280'}"></span>${t.identifier_type}: ${t.count}</div>`).join('');
    return `<div class="donut-card"><h4>By Identifier Type</h4><div class="donut-legend">${legendItems}</div></div>`;
  }

  function showToast(msg, type = 'success') {
    let toast = document.querySelector('.toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.className = 'toast';
      document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.className = `toast ${type} show`;
    setTimeout(() => toast.classList.remove('show'), 3000);
  }

  // --- Init ---
  loadViewData('overview');
  startAutoRefresh();
})();
