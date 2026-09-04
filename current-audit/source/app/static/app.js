(() => {
  const currentCsrf = () => document.getElementById('devfleet-csrf')?.dataset.token || '';
  const fetchWithTimeout = async (url, options = {}, timeoutMs = 10000) => {
    const controller = options.controller || new AbortController();
    const timer = setTimeout(() => controller.abort('timeout'), timeoutMs);
    try { return await fetch(url, { ...options, controller: undefined, signal: controller.signal }); }
    finally { clearTimeout(timer); }
  };
  const cleanupProjectRequests = () => {
    document.querySelectorAll('[data-project-logs]').forEach((node) => node._devfleetLogCleanup?.());
    document.querySelectorAll('.operation-banner').forEach((node) => node._devfleetOperationCleanup?.());
  };
  // The UI endpoint is optional; the same-origin operation endpoint remains the source of truth.

  // Navigation is deliberately limited to same-origin document links. Forms,
  // API links, external links, downloads, and modified clicks keep browser semantics.
  const main = document.querySelector('.app-main');
  const viewCache = new Map();
  let currentUrl = location.href;
  const isDocumentLink = (link, event) => {
    if (!link || !link.href || event.defaultPrevented || event.button !== 0 ||
        event.metaKey || event.ctrlKey || event.shiftKey || event.altKey ||
        link.target && link.target !== '_self' || link.hasAttribute('download') ||
        link.closest('form') || link.href.startsWith(`${location.origin}/api/`)) return false;
    const url = new URL(link.href, location.href);
    return url.origin === location.origin && url.protocol === location.protocol &&
      url.hash === '' || (url.origin === location.origin && url.protocol === location.protocol &&
      url.hash !== '' && url.pathname + url.search !== location.pathname + location.search);
  };
  const cacheCurrentView = () => {
    if (main) viewCache.set(currentUrl, { html: main.innerHTML, title: document.title, bodyClass: document.body.className });
  };
  const syncNavigation = () => {
    const params = new URL(location.href).searchParams;
    const view = params.get('view') || (location.pathname.startsWith('/projects/') ? 'project' : 'overview');
    document.querySelectorAll('.primary-nav a').forEach((link) => {
      const linkView = new URL(link.href, location.href).searchParams.get('view');
      link.classList.toggle('active', linkView === view || (view === 'project' && linkView === 'projects'));
    });
  };
  const applyDocument = (doc, url, replace = false) => {
    if (!main) return;
    cacheCurrentView();
    const nextMain = doc.querySelector('.app-main');
    if (!nextMain) { location.href = url; return; }
    cleanupProjectRequests(); window.__devfleetStopInfrastructure?.();
    main.replaceChildren(...Array.from(nextMain.childNodes).map((node) => node.cloneNode(true)));
    document.title = doc.title;
    document.body.className = doc.body.className;
    const nextCsrf = doc.getElementById('devfleet-csrf')?.dataset.token;
    if (nextCsrf !== undefined) document.getElementById('devfleet-csrf')?.setAttribute('data-token', nextCsrf);
    if (replace) history.replaceState({}, '', url); else history.pushState({}, '', url);
    currentUrl = location.href;
    viewCache.set(currentUrl, { html: main.innerHTML, title: document.title, bodyClass: document.body.className });
    initializeView();
    requestAnimationFrame(() => { if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView(); });
  };
  const navigate = async (url, replace = false) => {
    cacheCurrentView();
    const cached = viewCache.get(url);
    if (cached && main) {
      cleanupProjectRequests(); window.__devfleetStopInfrastructure?.();
      main.innerHTML = cached.html; document.title = cached.title; document.body.className = cached.bodyClass;
      if (replace) history.replaceState({}, '', url); else history.pushState({}, '', url);
      currentUrl = location.href; initializeView();
      return;
    }
    try {
      const response = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'text/html' } });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      applyDocument(await response.text().then((html) => new DOMParser().parseFromString(html, 'text/html')), url, replace);
    } catch (_) { location.href = url; }
  };
  document.addEventListener('click', (event) => {
    const link = event.target.closest('a');
    if (!isDocumentLink(link, event)) return;
    const url = new URL(link.href, location.href);
    if (url.href === location.href) return;
    event.preventDefault(); navigate(url.href);
  });
  window.addEventListener('popstate', () => navigate(location.href, true));
  syncNavigation();

  document.querySelectorAll('form[method="post"]').forEach((form) => {
    if (form.querySelector('input[name="csrf_token"]')) return;
    const input = document.createElement('input');
    input.type = 'hidden'; input.name = 'csrf_token'; input.value = currentCsrf();
    form.prepend(input);
  });

  const name = document.querySelector('input[name="display_name"]');
  const slug = document.querySelector('input[name="slug"]');
  if (name && slug) {
    let slugLocked = Boolean(slug.value);
    let lastGenerated = slug.value;
    slug.addEventListener('input', () => { slugLocked = slug.value !== lastGenerated; });
    name.addEventListener('input', () => {
      if (slugLocked) return;
      const generated = name.value.normalize('NFKD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-zA-Z0-9._\s-]/g, '')
        .trim().toLowerCase().replace(/[\s_]+/g, '-')
        .replace(/-+/g, '-').replace(/^-|-$/g, '').slice(0, 63);
      slug.value = generated; lastGenerated = generated;
    });
  }

  const advancedToggle = document.getElementById('advanced-mode-toggle');
  const advancedEnabled = localStorage.getItem('devfleet.advanced') === '1' || document.body.classList.contains('advanced-mode');
  document.body.classList.toggle('advanced-mode', advancedEnabled);
  if (advancedToggle) {
    advancedToggle.checked = advancedEnabled;
    advancedToggle.addEventListener('change', () => {
      const enabled = advancedToggle.checked;
      localStorage.setItem('devfleet.advanced', enabled ? '1' : '0');
      document.cookie = `devfleet_advanced=${enabled ? '1' : '0'}; Path=/; SameSite=Lax`;
      document.body.classList.toggle('advanced-mode', enabled);
    });
  }

  function initEnvironmentWizard() {
    const form = document.querySelector('[data-environment-wizard]');
    if (!form || form.dataset.enhanced === '1') return;
    form.dataset.enhanced = '1';
    const summary = form.querySelector('[data-review-summary]');
    const status = form.querySelector('[data-review-status]');
    const values = (name) => form.elements[name]?.value?.trim() || '';
    const render = () => {
      const profile = values('resource_profile');
      const cpu = values('custom_cpus') || 'auto';
      const ram = values('custom_ram_gb') || 'auto';
      const disk = values('custom_disk_gb') || 'auto';
      const pid = values('pid_limit') || '4096';
      const mode = values('pid_mode') || 'private';
      const runtime = values('runtime_isolation') || 'recommended runtime';
      const selected = profile ? `${profile} profile` : 'automatic recommendation';
      if (summary) summary.textContent = `${selected} · ${runtime} · ${cpu} CPU · ${ram} GB RAM · ${disk} GB disk · ${mode} PID · limit ${pid}`;
      if (status) { status.textContent = 'Review before provisioning'; status.className = 'status-badge neutral'; }
    };
    form.addEventListener('input', render); form.addEventListener('change', render); render();
  }

  function initExistingEnvironmentWizard() {
    const shell = document.querySelector('[data-existing-environment-wizard]');
    if (!shell || shell.dataset.enhanced === '1') return;
    const form = shell.parentElement.querySelector('form.environment-form');
    if (!form) return;
    shell.dataset.enhanced = '1';
    const slug = shell.dataset.projectSlug;
    const review = shell.querySelector('[data-environment-review]');
    const preflight = shell.querySelector('[data-environment-preflight]');
    const customNames = ['custom_cpus','custom_ram_gb','custom_disk_gb','pid_mode','pid_limit'];
    const profile = () => form.elements.resource_profile?.value || '';
    const confirmButton = form.querySelector('[data-environment-confirm]') || form.querySelector('button[type="submit"]');
    let lastPreflight = null;
    let stage = 'environment';
    const setStage = (next) => {
      stage = next; form.dataset.wizardStage = next;
      shell.querySelectorAll('[data-wizard-stage]').forEach((button) => {
        const active = button.dataset.wizardStage === next;
        button.classList.toggle('active', active); button.setAttribute('aria-current', active ? 'step' : 'false');
      });
      if (preflight && next === 'review') preflight.textContent = 'Running read-only workspace and capacity preflight…';
      if (confirmButton) confirmButton.textContent = next === 'confirm' ? 'Confirm environment assignment' : `Continue to ${next === 'environment' ? 'Resources' : next === 'resources' ? 'Review' : 'Confirm'}`;
      if (review && next !== 'review') review.textContent = `Stage ${next}: select the requested environment and resources.`;
    };
    const copyCustomValues = () => customNames.forEach((name) => {
      const source = shell.querySelector(`[name="${name}"]`); if (!source) return;
      let target = form.elements[name];
      if (!target) { target = document.createElement('input'); target.type = 'hidden'; target.name = name; form.append(target); }
      target.value = profile() === 'custom' ? (source.value || '') : '';
    });
    const toggleCustom = () => {
      const enabled = profile() === 'custom';
      shell.querySelectorAll('[data-custom-resources] input, [data-custom-resources] select').forEach((control) => { control.disabled = !enabled; });
      shell.querySelector('[data-custom-resources]')?.classList.toggle('disabled', !enabled);
      copyCustomValues();
    };
    const loadPreflight = async () => {
      try {
        copyCustomValues(); const query = new URLSearchParams(new FormData(form));
        const response = await fetch(`/ui/projects/${encodeURIComponent(slug)}/preflight?${query}`, { cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' } });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json(); lastPreflight = data; const limits = data.selected_limits || {};
        const current = data.current_runtime || {};
        if (review) review.textContent = `CURRENT → NEW\nProvider/runtime: ${current.runtime_provider || current.runtime_type || 'detected'} → ${data.selected_environment}\nWorkspace owner: ${current.workspace_user || 'devrunner'} → devrunner\nCPU/RAM/disk/PID: ${limits.cpus || '—'} / ${limits.memory || limits.memory_gb || '—'} / ${limits.disk_gb || '—'} / ${limits.pids || '—'}\nLifecycle/health: ${current.lifecycle_status || 'unknown'} / ${current.health_status || 'unknown'}\nActions: verified backup, source-runtime handling, provisioning/export, workspace and health verification, lifecycle restoration. Fallback: rollback retains the verified source/backup.`;
        const ready = Boolean(data.migration_ready);
        if (preflight) preflight.textContent = ready ? `Preflight ready: inspection, capacity, archive, compose, and worktree checks passed.` : `Preflight not ready: ${(data.blockers || ['unknown blocker']).join(' ')}`;
        if (confirmButton && stage === 'confirm') confirmButton.disabled = !ready;
      } catch (error) { lastPreflight = null; if (preflight) preflight.textContent = `Preflight unavailable: ${error.message}. Confirmation is disabled.`; if (confirmButton && stage === 'confirm') confirmButton.disabled = true; }
    };
    shell.querySelectorAll('[data-wizard-stage]').forEach((button) => button.addEventListener('click', async () => { setStage(button.dataset.wizardStage); if (stage === 'review' || stage === 'confirm') await loadPreflight(); }));
    form.addEventListener('change', toggleCustom); toggleCustom();
    form.addEventListener('submit', async (event) => {
      copyCustomValues();
      if (stage !== 'confirm') { event.preventDefault(); setStage(stage === 'environment' ? 'resources' : stage === 'resources' ? 'review' : 'confirm'); if (stage === 'review' || stage === 'confirm') await loadPreflight(); return; }
      if (!lastPreflight || !lastPreflight.migration_ready) { event.preventDefault(); await loadPreflight(); return; }
      if (!form.elements.wizard_confirmed) { const confirmed = document.createElement('input'); confirmed.type = 'hidden'; confirmed.name = 'wizard_confirmed'; confirmed.value = 'true'; form.append(confirmed); }
      const token = form.elements.csrf_token; if (token) token.value = currentCsrf();
      event.preventDefault();
      if (confirmButton) confirmButton.disabled = true;
      try {
        const response = await fetch(form.action, { method: 'POST', body: new URLSearchParams(new FormData(form)), credentials: 'same-origin', headers: { Accept: 'application/json', 'X-DevFleet-UI': '1' } });
        const data = await response.json().catch(() => ({})); if (!response.ok || !data.operation_id) throw new Error(data.detail || `HTTP ${response.status}`);
        if (preflight) preflight.textContent = 'Environment assignment queued. Tracking backup, runtime handling, provisioning, verification, health, lifecycle restoration, and rollback progress…';
        let pollDelay = 750; let failures = 0;
        const poll = async () => {
          try {
            const response = await fetch(`/ui/operations/${encodeURIComponent(data.operation_id)}`, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const operation = await response.json();
            const state = operation.state || operation.status || 'unknown';
            failures = 0;
            if (preflight) preflight.textContent = operation.message || state || 'Operation running';
            if (!['completed', 'failed', 'cancelled', 'interrupted'].includes(state)) {
              pollDelay = 750;
              setTimeout(poll, pollDelay);
            }
          } catch (error) {
            failures += 1;
            if (preflight) preflight.textContent = `Operation status temporarily unavailable: ${error.message}`;
            if (failures <= 5) { pollDelay = Math.min(8000, pollDelay * 2); setTimeout(poll, pollDelay); }
          }
        };
        poll();
      } catch (error) { if (preflight) preflight.textContent = `Environment assignment was not queued: ${error.message}`; if (confirmButton) confirmButton.disabled = false; }
    });
    setStage(stage);
  }

  function initProjectActions() {
    if (window.__devfleetProjectActionsBound) return;
    window.__devfleetProjectActionsBound = true;
    document.addEventListener('submit', async (event) => {
      const form = event.target.closest('form.project-action-form');
      if (!form) return;
      // One document-level listener covers SPA replacement and dynamic backup forms.
      event.preventDefault();
      if (form.dataset.pending === '1') return;
      form.dataset.pending = '1';
      const button = form.querySelector('button[type="submit"]') || form.querySelector('button');
      const action = form.dataset.projectAction || new URL(form.action, location.href).pathname.split('/').pop() || 'action';
      const slug = new URL(form.action, location.href).pathname.split('/')[2] || '';
      const originalLabel = button?.textContent || '';
      const status = form.querySelector('[data-project-action-status]') || document.createElement('span');
      status.dataset.projectActionStatus = '1'; status.className = 'project-action-status'; status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
      if (!status.parentElement) form.append(status);
      if (button) { button.disabled = true; button.setAttribute('aria-busy', 'true'); button.textContent = `${action.charAt(0).toUpperCase()}${action.slice(1)}…`; }
      status.textContent = `${action.charAt(0).toUpperCase()}${action.slice(1)} queued…`;
      try {
        const body = new URLSearchParams(new FormData(form)); body.set('csrf_token', currentCsrf());
        const response = await fetch(form.action, { method: 'POST', body, credentials: 'same-origin', headers: { Accept: 'application/json', 'X-DevFleet-UI': '1', 'Idempotency-Key': `project-action:${slug}:${action}` } });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.operation_id) throw new Error(data.detail || `HTTP ${response.status}`);
        status.textContent = 'Operation queued. Tracking progress…';
        const target = `/projects/${encodeURIComponent(slug)}?tab=${encodeURIComponent(new URL(location.href).searchParams.get('tab') || 'overview')}&operation=${encodeURIComponent(data.operation_id)}`;
        navigate(target);
      } catch (error) {
        form.dataset.pending = '0'; status.textContent = `${action.charAt(0).toUpperCase()}${action.slice(1)} failed. ${error.message}`; status.classList.add('error');
        if (button) { button.disabled = false; button.removeAttribute('aria-busy'); button.textContent = originalLabel; }
        const detail = document.createElement('details'); const summary = document.createElement('summary'); summary.textContent = 'Technical detail'; const pre = document.createElement('pre'); pre.textContent = String(error.stack || error.message || error); detail.append(summary, pre); form.append(detail);
      }
    });
  }

  function initializeView() {
    syncNavigation();
    initProjectActions();
    initEnvironmentWizard();
    initExistingEnvironmentWizard();
    initBackupHistory();
    initOperationProgress();
    initProjectLogs();
    initInfrastructure();
    requestAnimationFrame(() => { if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView(); });
  }

  function initBackupHistory() {
    const panel = document.querySelector('[data-backup-history]');
    if (!panel || panel.dataset.enhanced === '1') return;
    panel.dataset.enhanced = '1'; const list = panel.querySelector('[data-backup-list]'); const slug = panel.dataset.projectSlug;
    fetch(`/ui/projects/${encodeURIComponent(slug)}/backups`, { cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then((response) => { if (!response.ok) throw new Error(`HTTP ${response.status}`); return response.json(); })
      .then((data) => {
        list.replaceChildren(); const backups = data.backups || [];
        if (!backups.length) { list.textContent = 'No local verified restore points are recorded yet.'; return; }
        backups.forEach((backup) => {
          const row = document.createElement('div'); row.className = 'backup-history-row';
          const details = document.createElement('span'); details.textContent = `${backup.backup_id} · ${backup.status} · ${backup.archive_sha256 || 'no hash'}`;
          row.append(details);
          if (backup.status === 'eligible') {
            const form = document.createElement('form'); form.method = 'post'; form.action = `/projects/${encodeURIComponent(slug)}/restore-backup`; form.className = 'project-action-form';
            const csrf = document.createElement('input'); csrf.type = 'hidden'; csrf.name = 'csrf_token'; form.append(csrf);
            [['backup_id', backup.backup_id], ['confirm_restore', 'true']].forEach(([name, value]) => { const input = document.createElement('input'); input.type = 'hidden'; input.name = name; input.value = value; form.append(input); });
            const overwrite = document.createElement('label'); overwrite.className = 'checkbox-label'; const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.name = 'allow_overwrite'; checkbox.value = 'true'; overwrite.append(checkbox, document.createTextNode(' Allow overwrite')); form.append(overwrite);
            const button = document.createElement('button'); button.type = 'submit'; button.className = 'button ghost'; button.textContent = 'Restore'; form.append(button); row.append(form);
          }
          list.append(row);
        });
        initProjectActions();
      }).catch((error) => { list.textContent = `Backup history unavailable: ${error.message}`; });
  }

  function initOperationProgress() {
    const banner = document.querySelector('.operation-banner[data-operation-id]');
    if (!banner || banner.dataset.enhanced === '1') return;
    banner.dataset.enhanced = '1';
    const id = banner.dataset.operationId;
    const message = banner.querySelector('[data-operation-message]');
    const progress = banner.querySelector('[data-operation-progress]');
    const meta = banner.querySelector('[data-operation-meta]');
    let timer = null;
    let retry = 0;
    const load = async () => {
      try {
        const response = await fetch(`/operations/${encodeURIComponent(id)}`, { cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' } });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const op = await response.json();
        if (message) message.textContent = op.message || '';
        if (progress) { progress.style.width = `${Number(op.progress || 0)}%`; }
         if (meta) meta.textContent = `${op.progress || 0}% · ${op.state || 'unknown'}`;
         retry = 0;
         if (!['completed', 'failed', 'cancelled', 'interrupted'].includes(op.state)) timer = setTimeout(load, 1500);
         else if (banner.dataset.refreshed !== '1') { banner.dataset.refreshed = '1'; timer = setTimeout(() => { const refreshed = new URL(location.href); refreshed.searchParams.delete('operation'); navigate(refreshed.toString(), true); }, 500); }
       } catch (_) {
         retry = Math.min(retry + 1, 5); timer = setTimeout(load, Math.min(10000, 500 * (2 ** retry)));
       }
    };
    load();
    banner._devfleetOperationCleanup = () => { if (timer) clearTimeout(timer); };
  }

  function initProjectLogs() {
    const output = document.querySelector('.log-output[data-project-logs]');
    if (!output || output.dataset.enhanced === '1') return;
    output.dataset.enhanced = '1';
    const slug = output.dataset.projectLogs;
    const controls = document.createElement('div'); controls.className = 'log-controls';
    const tail = document.createElement('select'); tail.setAttribute('aria-label', 'Log lines');
    [50, 150, 300, 500].forEach((value) => { const option = new Option(`Last ${value} lines`, value); tail.add(option); });
    tail.value = localStorage.getItem('devfleet.project-log-tail') || '150';
    const refresh = document.createElement('button'); refresh.type = 'button'; refresh.className = 'button ghost'; refresh.textContent = 'Refresh';
    const pause = document.createElement('button'); pause.type = 'button'; pause.className = 'button ghost'; pause.textContent = 'Pause';
    const copy = document.createElement('button'); copy.type = 'button'; copy.className = 'button ghost'; copy.textContent = 'Copy';
    controls.append(tail, refresh, pause, copy); output.before(controls);
    let paused = false; let request = null; let activeController = null;
    const load = async () => {
      if (paused || request) return;
      // Human UI logs use the session-authenticated endpoint.  The machine API
      // intentionally remains token-protected and must never receive its token
      // through browser JavaScript.
      activeController = new AbortController();
      request = fetchWithTimeout(`/ui/projects/${encodeURIComponent(slug)}/logs?tail=${encodeURIComponent(tail.value)}`, { cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' }, controller: activeController }, 10000)
        .then(async (response) => { const data = await response.json().catch(() => ({})); if (response.status === 409) { paused = true; return data; } if (!response.ok) throw new Error(`HTTP ${response.status}`); return data; })
        .then((data) => { output.textContent = data.logs || 'No logs.'; })
        .catch((error) => { output.textContent = error.name === 'AbortError' ? 'Log request ended — the runtime changed state or the 10-second timeout was reached.' : `Logs failed: ${error.message}`; })
        .finally(() => { request = null; });
      await request;
    };
    tail.addEventListener('change', () => { localStorage.setItem('devfleet.project-log-tail', tail.value); load(); });
    refresh.addEventListener('click', load);
    pause.addEventListener('click', () => { paused = !paused; pause.textContent = paused ? 'Resume' : 'Pause'; if (!paused) load(); });
    copy.addEventListener('click', async () => { try { await navigator.clipboard.writeText(output.textContent); copy.textContent = 'Copied'; setTimeout(() => { copy.textContent = 'Copy'; }, 1200); } catch (_) { copy.textContent = 'Copy unavailable'; } });
    load();
    output._devfleetLogCleanup = () => { paused = true; activeController?.abort('navigation-or-state-change'); };
  }

  function initInfrastructure() {
  const nodesHost = document.getElementById('cluster-nodes');
  const table = document.querySelector('#container-table tbody');
  const nodeFilter = document.getElementById('container-node-filter');
  const refreshSelect = document.getElementById('refresh-interval');
  const refreshButton = document.getElementById('refresh-cluster');
  const updated = document.getElementById('cluster-updated');
  const details = document.getElementById('container-details');
  const detailsTitle = document.getElementById('container-details-title');
  const inspect = document.getElementById('container-inspect');
  const logs = document.getElementById('container-logs');
  const closeDetails = document.getElementById('close-container-details');
  if (!nodesHost && !table) return;
  window.__devfleetStopInfrastructure?.();

  const savedInterval = localStorage.getItem('devfleet.refresh.interval');
  if (refreshSelect && savedInterval && [...refreshSelect.options].some((o) => o.value === savedInterval)) refreshSelect.value = savedInterval;
  let timer = null;
  let cluster = { nodes: [], containers: [] };
  try { const seed = JSON.parse(document.getElementById('devfleet-cluster-data')?.textContent || '{}'); if (seed && typeof seed === 'object') cluster = seed; } catch (_) { /* retain empty snapshot */ }

  const text = (value) => document.createTextNode(String(value ?? ''));
  const cell = (value, className) => { const el = document.createElement('td'); if (className) el.className = className; el.append(text(value)); return el; };
  const metric = (label, value) => {
    const el = document.createElement('div'); el.className = 'metric';
    const nameEl = document.createElement('span'); nameEl.className = 'metric-label'; nameEl.append(text(label));
    const valueEl = document.createElement('strong'); valueEl.append(text(value));
    el.append(nameEl, valueEl); return el;
  };

  function renderNodes() {
    if (!nodesHost) return;
    nodesHost.replaceChildren();
    (cluster.nodes || []).forEach((node) => {
      const card = document.createElement('article'); card.className = 'node-card';
      const heading = document.createElement('div'); heading.className = 'node-heading';
      const title = document.createElement('h3'); title.append(text(node.friendly_name || node.id));
      const online = node.status === 'online' && node.reachable !== false;
      const badge = document.createElement('span'); badge.className = `status-badge ${online ? 'ok' : 'bad'}`; badge.append(text(online ? 'Available' : 'Offline — unavailable'));
      heading.append(title, badge); card.append(heading);
      const sub = document.createElement('p'); sub.className = 'muted'; sub.append(text(`${node.node || node.id} · ${node.role || 'node'}`)); card.append(sub);
      const metrics = document.createElement('div'); metrics.className = 'metrics';
      const system = node.system || {}; const docker = node.docker || {};
      metrics.append(metric('CPU', `${system.cpu_percent ?? '—'}%`), metric('Memory', `${system.memory_percent ?? '—'}%`), metric('Disk free', `${system.disk_free_gb ?? '—'} GB`), metric('Containers', String((node.containers || []).length)));
      card.append(metrics);
      const runtime = document.createElement('p'); runtime.className = 'node-runtime';
      runtime.append(text(node.role === 'vault' ? `Vault listener: ${(node.vault || {}).status || 'unknown'}` : `Docker: ${docker.ok ? (docker.mode || 'ready') : 'unavailable'}`)); card.append(runtime);
      if (node.error) { const error = document.createElement('p'); error.className = 'error'; error.append(text(node.error)); card.append(error); }
      if (node.role !== 'vault' && !online) { const note = document.createElement('p'); note.className = 'muted'; note.append(text('Destination selection disabled until this node is reachable.')); card.append(note); }
      nodesHost.append(card);
    });
    if (!cluster.nodes?.length) { const empty = document.createElement('p'); empty.className = 'muted'; empty.append(text('No cluster data returned.')); nodesHost.append(empty); }
  }

  function renderNodeFilter() {
    if (!nodeFilter) return;
    const current = nodeFilter.value || 'all';
    const options = [{ id: 'all', label: 'All nodes' }, ...(cluster.nodes || []).filter((n) => n.role !== 'vault').map((n) => ({ id: n.id, label: n.friendly_name || n.id }))];
    nodeFilter.replaceChildren();
    options.forEach((item) => { const option = document.createElement('option'); option.value = item.id; option.append(text(item.label)); nodeFilter.append(option); });
    nodeFilter.value = options.some((o) => o.id === current) ? current : 'all';
  }

  function renderContainers() {
    if (!table || !nodeFilter) return;
    table.replaceChildren();
    const filter = nodeFilter.value || 'all';
    const rows = (cluster.containers || []).filter((item) => filter === 'all' || item.node_id === filter);
    if (!rows.length) { const row = document.createElement('tr'); const empty = cell('No containers are registered on this node. A healthy empty node is different from an unavailable node.', 'muted'); empty.colSpan = 8; row.append(empty); table.append(row); return; }
    rows.forEach((item) => {
      const row = document.createElement('tr');
      row.append(cell(item.node_name || item.node_id), cell(item.name), cell(item.image), cell(`${item.state} · ${item.status}`), cell(item.cpu_percent), cell(`${item.memory_usage} (${item.memory_percent})`), cell(item.network_io));
      const actions = document.createElement('td'); actions.className = 'container-actions';
      ['start','stop','restart','pause','unpause'].forEach((action) => {
        const button = document.createElement('button'); button.type = 'button'; button.className = 'container-action'; button.dataset.action = action; button.dataset.ref = item.id; button.dataset.scope = item.control_scope; button.append(text(action)); actions.append(button);
      });
      const inspectButton = document.createElement('button'); inspectButton.type = 'button'; inspectButton.className = 'container-inspect'; inspectButton.dataset.ref = item.id; inspectButton.dataset.name = item.name; inspectButton.dataset.scope = item.control_scope; inspectButton.append(text('details')); actions.append(inspectButton);
      const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'container-action danger'; remove.dataset.action = 'remove'; remove.dataset.ref = item.id; remove.dataset.scope = item.control_scope; remove.append(text('remove')); actions.append(remove);
      row.append(actions); table.append(row);
    });
  }

  async function refreshCluster() {
    if (refreshButton) refreshButton.disabled = true;
    try {
      const response = await fetch('/cluster/status', { cache: 'no-store', credentials: 'same-origin' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      cluster = await response.json(); renderNodes(); renderNodeFilter(); renderContainers();
      if (updated) updated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    } catch (error) {
      if (updated) updated.textContent = `Refresh failed: ${error.message}`;
    } finally { if (refreshButton) refreshButton.disabled = false; }
  }

  function scheduleRefresh() {
    if (!refreshSelect) return;
    if (timer) clearInterval(timer); timer = null;
    localStorage.setItem('devfleet.refresh.interval', refreshSelect.value);
    const seconds = Number(refreshSelect.value);
    if (seconds > 0) timer = setInterval(refreshCluster, seconds * 1000);
  }

  async function showDetails(ref, name, scope) {
    details.hidden = false; detailsTitle.textContent = `${name || ref} · details`; inspect.textContent = 'Loading inspect…'; logs.textContent = 'Loading logs…';
    const prefix = scope === 'peer' ? '/peer' : '';
    try { const r = await fetch(`${prefix}/containers/${encodeURIComponent(ref)}/inspect`, { cache: 'no-store' }); if (!r.ok) throw new Error(`HTTP ${r.status}`); inspect.textContent = JSON.stringify(await r.json(), null, 2); } catch (e) { inspect.textContent = `Inspect failed: ${e.message}`; }
    try { const r = await fetch(`${prefix}/containers/${encodeURIComponent(ref)}/logs?tail=200`, { cache: 'no-store' }); if (!r.ok) throw new Error(`HTTP ${r.status}`); logs.textContent = (await r.json()).logs || 'No logs.'; } catch (e) { logs.textContent = `Logs failed: ${e.message}`; }
  }

  document.addEventListener('click', async (event) => {
    const inspectButton = event.target.closest('.container-inspect');
    if (inspectButton) return showDetails(inspectButton.dataset.ref, inspectButton.dataset.name, inspectButton.dataset.scope);
    const actionButton = event.target.closest('.container-action');
    if (!actionButton) return;
    const action = actionButton.dataset.action; const ref = actionButton.dataset.ref; const scope = actionButton.dataset.scope;
    if (action === 'remove' && !window.confirm('Remove this container? This cannot be undone.')) return;
    actionButton.disabled = true;
    try {
      const prefix = scope === 'peer' ? '/peer' : '';
       const body = new URLSearchParams({ csrf_token: currentCsrf() }); if (action === 'remove') body.set('confirm_remove', 'true');
      const response = await fetch(`${prefix}/containers/${encodeURIComponent(ref)}/${action}`, { method: 'POST', body, credentials: 'same-origin' });
      if (!response.ok) throw new Error((await response.text()).slice(-500));
      await refreshCluster();
    } catch (error) { window.alert(`Container action failed: ${error.message}`); }
    finally { actionButton.disabled = false; }
  });

  nodeFilter?.addEventListener('change', renderContainers);
  refreshButton?.addEventListener('click', refreshCluster);
  refreshSelect?.addEventListener('change', scheduleRefresh);
  closeDetails?.addEventListener('click', () => { details.hidden = true; });
  renderNodes(); renderNodeFilter(); renderContainers();
  const shouldRefresh = new URL(location.href).searchParams.get('view') === 'infrastructure';
  if (shouldRefresh) refreshCluster();
  scheduleRefresh();
  window.__devfleetStopInfrastructure = () => { if (timer) clearInterval(timer); timer = null; };
  }

  initializeView();
})();
