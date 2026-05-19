(() => {
  const form = document.getElementById('form');
  const dropzone = document.getElementById('dropzone');
  const dzEmpty = dropzone.querySelector('.dz-empty');
  const dzFilled = dropzone.querySelector('.dz-filled');
  const fileInput = document.getElementById('artifact');
  const pickLink = document.getElementById('pickLink');
  const fileNameEl = document.getElementById('fileName');
  const fileSizeEl = document.getElementById('fileSize');
  const clearFileBtn = document.getElementById('clearFile');
  const passwordsEl = document.getElementById('passwords');
  const pwCountEl = document.getElementById('pwCount');
  const submitBtn = document.getElementById('submitBtn');
  const cancelUploadBtn = document.getElementById('cancelUploadBtn');
  const cancelJobBtn = document.getElementById('cancelJobBtn');
  const resetBtn = document.getElementById('resetBtn');
  const sessionPill = document.getElementById('sessionPill');

  const pipelineCard = document.getElementById('pipelineCard');
  const statePill = document.getElementById('statePill');
  const stepUpload = document.getElementById('step-upload');
  const stepExtract = document.getElementById('step-extract');
  const stepDone = document.getElementById('step-done');
  const uploadDetail = document.getElementById('uploadDetail');
  const extractDetail = document.getElementById('extractDetail');
  const doneDetail = document.getElementById('doneDetail');

  const uploadProgressBlock = document.getElementById('uploadProgressBlock');
  const uploadBar = document.getElementById('uploadBar');
  const uploadPct = document.getElementById('uploadPct');
  const uploadStats = document.getElementById('uploadStats');

  const processCard = document.getElementById('processCard');
  const processBadge = document.getElementById('processBadge');
  const kvCommand = document.getElementById('kvCommand');
  const kvPid = document.getElementById('kvPid');
  const kvStarted = document.getElementById('kvStarted');
  const kvElapsed = document.getElementById('kvElapsed');
  const kvInput = document.getElementById('kvInput');
  const kvPasswords = document.getElementById('kvPasswords');
  const logEl = document.getElementById('log');
  const logCount = document.getElementById('logCount');

  const resultsCard = document.getElementById('resultsCard');
  const resultsMeta = document.getElementById('resultsMeta');
  const downloadsEl = document.getElementById('downloads');

  // ---------- helpers ----------
  const fmtBytes = (n) => {
    if (n == null) return '—';
    if (n < 1024) return n + ' B';
    const units = ['KB', 'MB', 'GB', 'TB'];
    let i = -1, v = n;
    do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
    return v.toFixed(v < 10 ? 2 : 1) + ' ' + units[i];
  };
  const fmtDuration = (ms) => {
    if (ms == null) return '—';
    const s = ms / 1000;
    if (s < 60) return s.toFixed(1) + ' s';
    const m = Math.floor(s / 60), sec = (s - m * 60).toFixed(0);
    return `${m}m ${sec}s`;
  };
  const fmtClock = (ts) => ts ? new Date(ts).toLocaleTimeString() : '—';

  let toastTimer = null;
  function toast(msg, kind) {
    document.querySelectorAll('.toast').forEach((n) => n.remove());
    const el = document.createElement('div');
    el.className = 'toast' + (kind ? ' is-' + kind : '');
    el.textContent = msg;
    document.body.appendChild(el);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.remove(), 4500);
  }

  // ---------- file selection ----------
  let selectedFile = null;
  function setFile(f) {
    selectedFile = f || null;
    if (f) {
      dropzone.classList.add('has-file');
      dzEmpty.hidden = true;
      dzFilled.hidden = false;
      fileNameEl.textContent = f.name;
      fileSizeEl.textContent = fmtBytes(f.size) + ' · ' + (f.type || 'application/octet-stream');
      submitBtn.disabled = false;
    } else {
      dropzone.classList.remove('has-file');
      dzEmpty.hidden = false;
      dzFilled.hidden = true;
      fileInput.value = '';
      submitBtn.disabled = true;
    }
  }

  dropzone.addEventListener('click', (e) => {
    if (selectedFile) return;
    if (e.target.closest('a, button')) return;
    fileInput.click();
  });
  dropzone.addEventListener('keydown', (e) => {
    if ((e.key === 'Enter' || e.key === ' ') && !selectedFile) {
      e.preventDefault(); fileInput.click();
    }
  });
  pickLink.addEventListener('click', (e) => { e.preventDefault(); fileInput.click(); });
  fileInput.addEventListener('change', () => {
    const f = fileInput.files[0];
    if (f) setFile(f);
  });
  clearFileBtn.addEventListener('click', () => setFile(null));

  ['dragenter', 'dragover'].forEach((ev) => {
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault(); e.stopPropagation();
      if (!selectedFile) dropzone.classList.add('is-dragging');
    });
  });
  ['dragleave', 'drop'].forEach((ev) => {
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault(); e.stopPropagation();
      dropzone.classList.remove('is-dragging');
    });
  });
  dropzone.addEventListener('drop', (e) => {
    if (selectedFile) return;
    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) setFile(f);
  });

  // ---------- passwords counter ----------
  function refreshPwCount() {
    const entries = passwordsEl.value
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && !s.startsWith('#'));
    pwCountEl.textContent = entries.length + ' ' + (entries.length === 1 ? 'entry' : 'entries');
  }
  passwordsEl.addEventListener('input', refreshPwCount);
  refreshPwCount();

  // ---------- state machine ----------
  let xhr = null;
  let elapsedTimer = null;
  let jobStartedAt = null;
  let lastState = 'idle';

  function setUiState(state) {
    lastState = state;
    statePill.className = 'pill state-pill is-' + state;
    statePill.textContent = state;
    pipelineCard.hidden = state === 'idle';

    [stepUpload, stepExtract, stepDone].forEach((el) => el.classList.remove('is-active', 'is-done', 'is-failed'));
    if (state === 'uploading') stepUpload.classList.add('is-active');
    else if (state === 'running') { stepUpload.classList.add('is-done'); stepExtract.classList.add('is-active'); }
    else if (state === 'done')    { stepUpload.classList.add('is-done'); stepExtract.classList.add('is-done'); stepDone.classList.add('is-done'); }
    else if (state === 'failed' || state === 'cancelled') {
      stepUpload.classList.add('is-done');
      stepExtract.classList.add('is-failed');
    }
  }

  function startElapsedTicker() {
    stopElapsedTicker();
    elapsedTimer = setInterval(() => {
      if (!jobStartedAt) return;
      kvElapsed.textContent = fmtDuration(Date.now() - jobStartedAt);
    }, 100);
  }
  function stopElapsedTicker() {
    if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
  }

  // ---------- upload ----------
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!selectedFile) return;
    submitBtn.disabled = true;
    cancelUploadBtn.hidden = false;
    setUiState('uploading');
    processCard.hidden = true;
    resultsCard.hidden = true;
    downloadsEl.innerHTML = '';
    logEl.textContent = '';
    logCount.textContent = '0 lines';
    uploadProgressBlock.hidden = false;
    uploadBar.style.width = '0%';
    uploadPct.textContent = '0%';
    uploadStats.textContent = 'starting…';
    uploadDetail.textContent = 'uploading';
    extractDetail.textContent = 'queued';
    doneDetail.textContent = 'waiting';

    const fd = new FormData();
    fd.append('artifact', selectedFile);
    fd.append('passwords', passwordsEl.value);

    xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload');
    const uploadStartedAt = Date.now();
    let lastLoaded = 0;
    let lastTickAt = uploadStartedAt;
    let lastSpeed = 0;

    xhr.upload.onprogress = (ev) => {
      if (!ev.lengthComputable) return;
      const pct = (ev.loaded / ev.total) * 100;
      uploadBar.style.width = pct + '%';
      uploadPct.textContent = pct.toFixed(1) + '%';
      const now = Date.now();
      const dt = (now - lastTickAt) / 1000;
      if (dt > 0.25) {
        const instSpeed = (ev.loaded - lastLoaded) / dt;
        // EMA smoothing avoids jumpy speed readouts.
        lastSpeed = lastSpeed === 0 ? instSpeed : lastSpeed * 0.6 + instSpeed * 0.4;
        lastLoaded = ev.loaded;
        lastTickAt = now;
      }
      const remaining = lastSpeed > 0 ? (ev.total - ev.loaded) / lastSpeed : null;
      uploadStats.textContent =
        `${fmtBytes(ev.loaded)} of ${fmtBytes(ev.total)}` +
        (lastSpeed > 0 ? ` · ${fmtBytes(lastSpeed)}/s` : '') +
        (remaining != null && isFinite(remaining) ? ` · ${fmtDuration(remaining * 1000)} left` : '');
      uploadDetail.textContent = `${pct.toFixed(0)}% · ${fmtBytes(lastSpeed)}/s`;
    };

    xhr.onload = () => {
      cancelUploadBtn.hidden = true;
      const x = xhr; xhr = null;
      if (x.status >= 200 && x.status < 300) {
        uploadDetail.textContent = `done · ${fmtBytes(selectedFile.size)} in ${fmtDuration(Date.now() - uploadStartedAt)}`;
        uploadProgressBlock.hidden = true;
        // Server-side state arrives via SSE; just flip to running while we wait.
        setUiState('running');
        extractDetail.textContent = 'running';
        processCard.hidden = false;
      } else {
        let msg = 'Upload failed (HTTP ' + x.status + ').';
        try { msg = JSON.parse(x.responseText).error || msg; } catch (_) {}
        toast(msg, 'error');
        setUiState('failed');
        uploadDetail.textContent = msg;
        submitBtn.disabled = false;
      }
    };
    xhr.onerror = () => {
      cancelUploadBtn.hidden = true;
      xhr = null;
      toast('Network error during upload.', 'error');
      setUiState('failed');
      submitBtn.disabled = false;
    };
    xhr.onabort = () => {
      cancelUploadBtn.hidden = true;
      xhr = null;
      toast('Upload cancelled.');
      setUiState('idle');
      uploadProgressBlock.hidden = true;
      submitBtn.disabled = false;
    };
    xhr.send(fd);
  });

  cancelUploadBtn.addEventListener('click', () => {
    if (xhr) { xhr.abort(); xhr = null; }
  });

  cancelJobBtn.addEventListener('click', async () => {
    cancelJobBtn.disabled = true;
    try {
      const r = await fetch('/api/cancel', { method: 'POST' });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        toast(j.error || 'Could not cancel.', 'error');
      } else {
        toast('Stopping process…');
      }
    } finally {
      cancelJobBtn.disabled = false;
    }
  });

  resetBtn.addEventListener('click', async () => {
    await fetch('/api/reset', { method: 'POST' }).catch(() => {});
    location.reload();
  });

  // ---------- SSE wiring ----------
  let es = null;
  function connectEvents() {
    if (es) try { es.close(); } catch (_) {}
    es = new EventSource('/api/events');
    es.addEventListener('state', (ev) => applyState(JSON.parse(ev.data)));
    es.addEventListener('log', (ev) => appendLog([JSON.parse(ev.data)]));
    es.addEventListener('log-replay', (ev) => { logEl.textContent = ''; appendLog(JSON.parse(ev.data)); });
    es.addEventListener('outputs', (ev) => renderOutputs(JSON.parse(ev.data)));
    es.addEventListener('closed', () => { try { es.close(); } catch (_) {} es = null; });
    es.onerror = () => {
      // Browser auto-reconnects; we just close to avoid leaks if the session is dead.
    };
  }

  function applyState(snap) {
    sessionPill.textContent = 'session ' + (snap.sessionId ? snap.sessionId.slice(0, 8) : '?');
    sessionPill.title = 'Session ' + snap.sessionId + '\nstarted ' + fmtClock(snap.sessionStartedAt);

    const j = snap.job;
    if (!j) {
      jobStartedAt = null;
      stopElapsedTicker();
      processCard.hidden = true;
      resultsCard.hidden = true;
      cancelJobBtn.hidden = true;
      if (lastState !== 'uploading') setUiState('idle');
      return;
    }

    pipelineCard.hidden = false;
    processCard.hidden = false;
    kvCommand.textContent = j.command + ' ' + (j.args || []).join(' ');
    kvPid.textContent = j.pid != null ? String(j.pid) : '—';
    kvStarted.textContent = fmtClock(j.startedAt);
    kvInput.textContent = j.inputName + ' · ' + fmtBytes(j.inputSize);
    kvPasswords.textContent = j.passwordCount > 0
      ? `${j.passwordCount} configured · via ${j.passwordTransport === 'env' ? 'env var (no disk)' : 'tmpfs file (shredded)'}`
      : 'none';

    jobStartedAt = j.startedAt || null;

    if (j.state === 'running') {
      setUiState('running');
      extractDetail.textContent = 'running · pid ' + j.pid;
      processBadge.textContent = 'running · pid ' + j.pid;
      cancelJobBtn.hidden = false;
      startElapsedTicker();
    } else {
      stopElapsedTicker();
      cancelJobBtn.hidden = true;
      const totalElapsed = (j.finishedAt && j.startedAt) ? j.finishedAt - j.startedAt : null;
      kvElapsed.textContent = fmtDuration(totalElapsed);

      if (j.state === 'done') {
        setUiState('done');
        extractDetail.textContent = 'completed in ' + fmtDuration(totalElapsed);
        doneDetail.textContent = (j.outputs && j.outputs.length)
          ? `${j.outputs.length} output file${j.outputs.length === 1 ? '' : 's'}`
          : 'no output files';
        processBadge.textContent = 'exit 0 · ' + fmtDuration(totalElapsed);
      } else if (j.state === 'cancelled') {
        setUiState('cancelled');
        extractDetail.textContent = 'cancelled (' + (j.signal || 'SIGTERM') + ')';
        doneDetail.textContent = '—';
        processBadge.textContent = 'cancelled · ' + (j.signal || 'SIGTERM');
        toast('Process cancelled.', 'error');
      } else if (j.state === 'failed') {
        setUiState('failed');
        extractDetail.textContent = `failed · exit code ${j.exitCode}`;
        doneDetail.textContent = j.error ? j.error : '—';
        processBadge.textContent = `exit ${j.exitCode}`;
        toast(`extract-sbom exited with code ${j.exitCode}`, 'error');
      }

      submitBtn.disabled = !selectedFile;
    }

    renderOutputs(j.outputs || []);
  }

  function appendLog(entries) {
    if (!entries || !entries.length) return;
    const atBottom = (logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight) < 10;
    const frag = document.createDocumentFragment();
    for (const e of entries) {
      const span = document.createElement('span');
      span.className = e.stream === 'stderr' ? 'err' : '';
      span.textContent = e.line + '\n';
      frag.appendChild(span);
    }
    logEl.appendChild(frag);
    // Trim DOM if it grows huge.
    while (logEl.childNodes.length > 4000) logEl.removeChild(logEl.firstChild);
    logCount.textContent = logEl.childNodes.length + ' lines';
    if (atBottom) logEl.scrollTop = logEl.scrollHeight;
  }

  function renderOutputs(files) {
    downloadsEl.innerHTML = '';
    if (!files || !files.length) {
      resultsCard.hidden = lastState !== 'done';
      if (!resultsCard.hidden) {
        const li = document.createElement('li');
        li.innerHTML = '<span class="muted">No output files were produced.</span>';
        downloadsEl.appendChild(li);
      }
      resultsMeta.textContent = '0 files';
      return;
    }
    resultsCard.hidden = false;
    let total = 0;
    for (const f of files) {
      total += f.size || 0;
      const li = document.createElement('li');
      const left = document.createElement('div');
      left.innerHTML = `<div class="dl-name">${escapeHtml(f.name)}</div>` +
                       `<div class="filesize">${fmtBytes(f.size)}</div>`;
      const a = document.createElement('a');
      a.href = '/api/download/' + encodeURIComponent(f.name);
      a.download = f.name;
      a.className = 'dl-btn';
      a.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Download';
      li.appendChild(left);
      li.appendChild(a);
      downloadsEl.appendChild(li);
    }
    resultsMeta.textContent = `${files.length} file${files.length === 1 ? '' : 's'} · ${fmtBytes(total)}`;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  // Best-effort cleanup when the tab closes (GET / already cleans on reload).
  window.addEventListener('pagehide', () => {
    navigator.sendBeacon && navigator.sendBeacon('/api/reset');
  });

  connectEvents();
})();
