// SBOM Extractor — TypeScript frontend
// Compiled to public/dist/app.js by tsconfig.frontend.json
// tus-js-client loaded as a UMD bundle (/vendor/tus.min.js) before this module.

declare const tus: {
  Upload: new (file: File, opts: {
    endpoint: string;
    metadata?: Record<string, string>;
    chunkSize?: number;
    retryDelays?: number[];
    withCredentials?: boolean;
    credentials?: 'same-origin' | 'include' | 'omit';
    onProgress?: (bytesSent: number, bytesTotal: number) => void;
    onError?: (err: Error) => void;
    onSuccess?: () => void;
    headers?: Record<string, string>;
  }) => {
    start(): void;
    abort(): Promise<void>;
    findPreviousUploads(): Promise<unknown[]>;
    resumeFromPreviousUpload(upload: unknown): void;
    url: string | null;
  };
};

// ─────────────────────────────────────────────
// Shared types (mirrors src/types.ts, browser-only subset)
// ─────────────────────────────────────────────
type JobState = 'queued' | 'running' | 'done' | 'failed' | 'cancelled';
type SessionState = 'idle' | JobState;
type PasswordTransport = 'none' | 'env' | 'file';
type SandboxKind = 'none' | 'bwrap' | 'firejail';

interface OutputFile {
  name: string;
  size: number;
  mtime: number;
}

interface JobSnapshot {
  id: string;
  state: JobState;
  command: string;
  args: string[];
  pid: number | null;
  inputName: string;
  inputSize: number;
  passwordCount: number;
  passwordTransport: PasswordTransport;
  createdAt: number;
  startedAt: number | null;
  finishedAt: number | null;
  exitCode: number | null;
  signal: string | null;
  error: string | null;
  outputs: OutputFile[];
  phase: string | null;
  progress: number | null;
  sandbox: SandboxKind;
}

interface PendingUpload {
  id: string;
  name: string;
  size: number;
}

interface SessionSnapshot {
  sessionId: string;
  sessionStartedAt: number;
  state: SessionState;
  currentJobId: string | null;
  pendingUpload: PendingUpload | null;
  jobs: JobSnapshot[];
}

interface LogEntry {
  t: number;
  stream: 'stdout' | 'stderr';
  line: string;
}

// ─────────────────────────────────────────────
// Session-Id und Version aus den Meta-Tags ziehen.
// Der Server setzt {{SID}} / {{VERSION}} pro Request ein. Cookie ist
// der Primärweg, dieses Token ist der Fallback für Setups, in denen das
// Cookie unterwegs gefiltert wird (Reverse-Proxy / Tunnel).
// ─────────────────────────────────────────────
const SID: string = (
  document.querySelector('meta[name="x-sid"]') as HTMLMetaElement | null
)?.content ?? '';
const APP_VERSION: string = (
  document.querySelector('meta[name="x-version"]') as HTMLMetaElement | null
)?.content ?? '';

// Pin "v…"-Placeholder durch den echten Wert ersetzen, sobald das Modul lädt.
{
  const vp = document.getElementById('versionPill');
  if (vp && APP_VERSION) {
    vp.textContent = 'v' + APP_VERSION;
    vp.title = 'App-Version ' + APP_VERSION;
  }
}

// Hilfsfunktion: Fetch mit Session-Header und Same-Origin-Credentials.
function authedFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers ?? {});
  if (SID) headers.set('X-Session-Id', SID);
  return fetch(input, { ...init, credentials: 'same-origin', headers });
}

// Hilfsfunktion: ?sid= an eine URL anhängen (für Endpoints, die keine Header
// transportieren können — SSE und direkte <a href>-Downloads).
function withSid(url: string): string {
  if (!SID) return url;
  const sep = url.includes('?') ? '&' : '?';
  return `${url}${sep}sid=${encodeURIComponent(SID)}`;
}

// ─────────────────────────────────────────────
// Deutsche Beschriftungen
// ─────────────────────────────────────────────
const STATE_LABEL: Record<string, string> = {
  idle:       'bereit',
  queued:     'wartet',
  running:    'läuft',
  done:       'fertig',
  failed:     'fehlgeschlagen',
  cancelled:  'abgebrochen',
};

const PHASE_LABEL: Record<string, string> = {
  'starting':              'startet',
  'extracting':            'entpackt',
  'cataloging':            'katalogisiert',
  'vulnerability scan':    'Schwachstellen-Scan',
  'writing report':        'schreibt Bericht',
  'finishing':             'schließt ab',
};

// Translate a server-provided state for display. Falls back to the raw key.
function tState(s: string | null | undefined): string {
  if (!s) return '—';
  return STATE_LABEL[s] ?? s;
}
function tPhase(p: string | null | undefined): string {
  if (!p) return '';
  return PHASE_LABEL[p] ?? p;
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
function fmtBytes(n: number | null | undefined): string {
  if (n == null) return '—';
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  let v = n;
  do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
  return v.toFixed(v < 10 ? 2 : 1) + ' ' + units[i];
}

function fmtDuration(ms: number | null | undefined): string {
  if (ms == null) return '—';
  const s = ms / 1000;
  if (s < 60) return s.toFixed(1) + ' s';
  const m = Math.floor(s / 60);
  const sec = (s - m * 60).toFixed(0);
  return `${m}m ${sec}s`;
}

function fmtClock(ts: number | null | undefined): string {
  return ts ? new Date(ts).toLocaleTimeString() : '—';
}

function escapeHtml(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  } as Record<string, string>)[c] ?? c);
}

function qs<T extends HTMLElement>(sel: string, root: ParentNode = document): T {
  const el = root.querySelector<T>(sel);
  if (!el) throw new Error(`Element not found: ${sel}`);
  return el;
}

// ─────────────────────────────────────────────
// Toast
// ─────────────────────────────────────────────
let toastTimer: ReturnType<typeof setTimeout> | null = null;
function toast(msg: string, kind?: 'error' | 'ok'): void {
  document.querySelectorAll('.toast').forEach((n) => n.remove());
  const el = document.createElement('div');
  el.className = 'toast' + (kind ? ' is-' + kind : '');
  el.textContent = msg;
  document.body.appendChild(el);
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.remove(), 4500);
}

// ─────────────────────────────────────────────
// DOM refs — upload card
// ─────────────────────────────────────────────
const dropzone = qs<HTMLDivElement>('#dropzone');
const dzEmpty = qs<HTMLDivElement>('.dz-empty', dropzone);
const dzFilled = qs<HTMLDivElement>('.dz-filled', dropzone);
const fileInput = qs<HTMLInputElement>('#artifact');
const pickLink = qs<HTMLAnchorElement>('#pickLink');
const fileNameEl = qs<HTMLDivElement>('#fileName');
const fileSizeEl = qs<HTMLDivElement>('#fileSize');
const clearFileBtn = qs<HTMLButtonElement>('#clearFile');
const passwordsEl = qs<HTMLTextAreaElement>('#passwords');
const pwCountEl = qs<HTMLSpanElement>('#pwCount');
const submitBtn = qs<HTMLButtonElement>('#submitBtn');
const cancelUploadBtn = qs<HTMLButtonElement>('#cancelUploadBtn');
// Upload progress (inside uploadCard)
const uploadProgressBlock = qs<HTMLDivElement>('#uploadProgressBlock');
const uploadBar = qs<HTMLDivElement>('#uploadBar');
const uploadPct = qs<HTMLSpanElement>('#uploadPct');
const uploadStats = qs<HTMLDivElement>('#uploadStats');

// ─────────────────────────────────────────────
// DOM refs — topbar
// ─────────────────────────────────────────────
const sessionPill = qs<HTMLSpanElement>('#sessionPill');
const resetBtn = qs<HTMLButtonElement>('#resetBtn');

// ─────────────────────────────────────────────
// DOM refs — active job panel
// ─────────────────────────────────────────────
const activeJobSection = qs<HTMLElement>('#activeJob');
const ajStateBadge = qs<HTMLSpanElement>('#ajStateBadge');
const ajInputName = qs<HTMLSpanElement>('#ajInputName');
const ajInputSize = qs<HTMLSpanElement>('#ajInputSize');
const ajCommand = qs<HTMLSpanElement>('#ajCommand');
const ajPid = qs<HTMLSpanElement>('#ajPid');
const ajElapsed = qs<HTMLSpanElement>('#ajElapsed');
const ajPhaseLabel = qs<HTMLSpanElement>('#ajPhaseLabel');
const ajProgressTrack = qs<HTMLDivElement>('#ajProgressTrack');
const ajProgressBar = qs<HTMLDivElement>('#ajProgressBar');
const ajProgressPct = qs<HTMLSpanElement>('#ajProgressPct');
const ajLogEl = qs<HTMLPreElement>('#ajLog');
const ajLogCount = qs<HTMLSpanElement>('#ajLogCount');
const cancelJobBtn = qs<HTMLButtonElement>('#cancelJobBtn');

// ─────────────────────────────────────────────
// DOM refs — job history
// ─────────────────────────────────────────────
const jobHistoryList = qs<HTMLOListElement>('#jobHistory');

// ─────────────────────────────────────────────
// File selection
// ─────────────────────────────────────────────
let selectedFile: File | null = null;

function setFile(f: File | null): void {
  selectedFile = f;
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
  if ((e.target as Element).closest('a, button')) return;
  fileInput.click();
});
dropzone.addEventListener('keydown', (e: KeyboardEvent) => {
  if ((e.key === 'Enter' || e.key === ' ') && !selectedFile) {
    e.preventDefault();
    fileInput.click();
  }
});
pickLink.addEventListener('click', (e) => { e.preventDefault(); fileInput.click(); });
fileInput.addEventListener('change', () => {
  const f = fileInput.files?.[0];
  if (f) setFile(f);
});
clearFileBtn.addEventListener('click', () => setFile(null));

['dragenter', 'dragover'].forEach((ev) => {
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    (e as DragEvent).stopPropagation();
    if (!selectedFile) dropzone.classList.add('is-dragging');
  });
});
['dragleave', 'drop'].forEach((ev) => {
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    (e as DragEvent).stopPropagation();
    dropzone.classList.remove('is-dragging');
  });
});
dropzone.addEventListener('drop', (e: DragEvent) => {
  if (selectedFile) return;
  const f = e.dataTransfer?.files[0];
  if (f) setFile(f);
});

// ─────────────────────────────────────────────
// Password counter
// ─────────────────────────────────────────────
function refreshPwCount(): void {
  const entries = passwordsEl.value
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && !s.startsWith('#'));
  pwCountEl.textContent = entries.length + ' ' + (entries.length === 1 ? 'Eintrag' : 'Einträge');
}
passwordsEl.addEventListener('input', refreshPwCount);
refreshPwCount();

// ─────────────────────────────────────────────
// Elapsed ticker for active job
// ─────────────────────────────────────────────
let elapsedRafId: number | null = null;
let activeJobStartedAt: number | null = null;

function startElapsedTicker(): void {
  stopElapsedTicker();
  function tick(): void {
    if (activeJobStartedAt) {
      ajElapsed.textContent = fmtDuration(Date.now() - activeJobStartedAt);
    }
    elapsedRafId = requestAnimationFrame(tick);
  }
  elapsedRafId = requestAnimationFrame(tick);
}

function stopElapsedTicker(): void {
  if (elapsedRafId !== null) {
    cancelAnimationFrame(elapsedRafId);
    elapsedRafId = null;
  }
}

// ─────────────────────────────────────────────
// Active-job log (per-job)
// ─────────────────────────────────────────────
// Tracks which job the active-job panel is currently displaying
let activeJobId: string | null = null;

function appendActiveLog(entries: LogEntry[]): void {
  if (!entries.length) return;
  const atBottom = (ajLogEl.scrollHeight - ajLogEl.scrollTop - ajLogEl.clientHeight) < 10;
  const frag = document.createDocumentFragment();
  for (const e of entries) {
    const span = document.createElement('span');
    span.className = e.stream === 'stderr' ? 'err' : '';
    span.textContent = e.line + '\n';
    frag.appendChild(span);
  }
  ajLogEl.appendChild(frag);
  // Keep DOM bounded
  while (ajLogEl.childNodes.length > 4000) ajLogEl.removeChild(ajLogEl.firstChild!);
  ajLogCount.textContent = ajLogEl.childNodes.length + ' Zeilen';
  if (atBottom) ajLogEl.scrollTop = ajLogEl.scrollHeight;
}

function clearActiveLog(): void {
  ajLogEl.textContent = '';
  ajLogCount.textContent = '0 Zeilen';
}

// ─────────────────────────────────────────────
// Active-job panel rendering
// ─────────────────────────────────────────────
function renderActiveJob(job: JobSnapshot | null): void {
  if (!job || (job.state !== 'queued' && job.state !== 'running')) {
    activeJobSection.hidden = true;
    stopElapsedTicker();
    return;
  }

  // If job changed, reset log
  if (activeJobId !== job.id) {
    activeJobId = job.id;
    clearActiveLog();
  }

  activeJobSection.hidden = false;

  // State badge (translated)
  ajStateBadge.textContent = tState(job.state);
  ajStateBadge.className = 'state-badge is-' + job.state;

  // Input info
  ajInputName.textContent = job.inputName;
  ajInputSize.textContent = fmtBytes(job.inputSize);

  // Command + PID
  ajCommand.textContent = job.command + ' ' + (job.args || []).join(' ');
  ajPid.textContent = job.pid != null ? String(job.pid) : '—';

  // Elapsed
  activeJobStartedAt = job.startedAt;
  if (job.state === 'running' && job.startedAt) {
    startElapsedTicker();
  } else {
    stopElapsedTicker();
    ajElapsed.textContent = '—';
  }

  // Phase + progress
  renderProgress(job.phase, job.progress);
}

function renderProgress(phase: string | null, progress: number | null): void {
  ajPhaseLabel.textContent = tPhase(phase);
  if (progress != null) {
    ajProgressTrack.classList.remove('indeterminate');
    ajProgressBar.style.width = progress + '%';
    ajProgressPct.textContent = progress.toFixed(0) + ' %';
  } else {
    ajProgressTrack.classList.add('indeterminate');
    ajProgressBar.style.width = '100%';
    ajProgressPct.textContent = '';
  }
}

// ─────────────────────────────────────────────
// Job history rendering
// ─────────────────────────────────────────────
// We keep a map of jobId -> <li> element for incremental updates
const jobCardMap = new Map<string, HTMLLIElement>();

function renderJobHistory(jobs: JobSnapshot[]): void {
  // Render newest-first
  const sorted = [...jobs].reverse();

  // Remove cards for jobs that no longer exist
  for (const [id, li] of jobCardMap) {
    if (!jobs.find((j) => j.id === id)) {
      li.remove();
      jobCardMap.delete(id);
    }
  }

  for (let i = 0; i < sorted.length; i++) {
    const job = sorted[i];
    let li = jobCardMap.get(job.id);
    if (!li) {
      li = document.createElement('li');
      li.className = 'job-card';
      li.dataset.jobId = job.id;
      // Attach expand toggle
      li.addEventListener('click', (e) => {
        // Don't toggle if clicking a link or button
        if ((e.target as Element).closest('a, button')) return;
        li!.classList.toggle('is-expanded');
      });
      jobCardMap.set(job.id, li);
    }
    updateJobCard(li, job);

    // Insert in correct position (newest first)
    const existing = jobHistoryList.children[i] as HTMLElement | undefined;
    if (!existing) {
      jobHistoryList.appendChild(li);
    } else if (existing !== li) {
      jobHistoryList.insertBefore(li, existing);
    }
  }
}

function updateJobCard(li: HTMLLIElement, job: JobSnapshot): void {
  const runtime = job.startedAt && job.finishedAt
    ? fmtDuration(job.finishedAt - job.startedAt)
    : job.startedAt ? 'läuft …' : '—';

  // Files that we render in-browser as a styled HTML page get an extra
  // "Ansicht" button in front of the regular Download link.
  const isViewable = (name: string): boolean => {
    const n = name.toLowerCase();
    return n.endsWith('.md') || n.endsWith('.markdown') ||
           n.endsWith('.json') || n.endsWith('.txt') || n.endsWith('.log');
  };

  const outputsHtml = (job.outputs || []).map((f) => {
    // ?sid= damit Direkt-Navigationen ohne Cookie nicht ins 440 laufen
    const dl = withSid(`/api/download/${encodeURIComponent(job.id)}/${encodeURIComponent(f.name)}`);
    const view = withSid(`/api/view/${encodeURIComponent(job.id)}/${encodeURIComponent(f.name)}`);
    const viewBtn = isViewable(f.name)
      ? `<a href="${view}" target="_blank" rel="noopener" class="dl-btn">
           <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
             <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
             <circle cx="12" cy="12" r="3"/>
           </svg>Ansicht
         </a>`
      : '';
    return `<li class="dl-item">
      <div class="dl-name">${escapeHtml(f.name)}</div>
      <div class="filesize">${fmtBytes(f.size)}</div>
      ${viewBtn}
      <a href="${dl}" download="${escapeHtml(f.name)}" class="dl-btn">
        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
          <polyline points="7 10 12 15 17 10"/>
          <line x1="12" y1="15" x2="12" y2="3"/>
        </svg>Herunterladen
      </a>
    </li>`;
  }).join('');

  const errorHtml = job.error
    ? `<div class="job-error muted small">${escapeHtml(job.error)}</div>`
    : '';

  li.innerHTML = `
    <div class="job-card-summary">
      <span class="state-badge is-${job.state}">${escapeHtml(tState(job.state))}</span>
      <span class="job-card-name">${escapeHtml(job.inputName)}</span>
      <span class="job-card-size muted small">${fmtBytes(job.inputSize)}</span>
      <span class="job-card-runtime muted small">${escapeHtml(runtime)}</span>
      <span class="job-card-toggle" aria-hidden="true">▸</span>
    </div>
    <div class="job-card-detail">
      ${errorHtml}
      ${outputsHtml ? `<ul class="downloads job-downloads">${outputsHtml}</ul>` : '<p class="muted small">Keine Ausgabedateien.</p>'}
    </div>
  `;
}

// ─────────────────────────────────────────────
// tus upload state
// ─────────────────────────────────────────────
type TusUpload = ReturnType<typeof tus.Upload.prototype.constructor> extends never
  ? never
  : { start(): void; abort(): Promise<void>; findPreviousUploads(): Promise<unknown[]>; resumeFromPreviousUpload(u: unknown): void; url: string | null; };

// We declare it manually to avoid the TS complexity above
let tusUpload: { start(): void; abort(): Promise<void>; url: string | null } | null = null;
let uploadInProgress = false;

// ─────────────────────────────────────────────
// Submit handler — tus upload then POST /api/jobs
// ─────────────────────────────────────────────
qs<HTMLFormElement>('#form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!selectedFile || uploadInProgress) return;

  uploadInProgress = true;
  submitBtn.disabled = true;
  cancelUploadBtn.hidden = false;

  uploadProgressBlock.hidden = false;
  uploadBar.style.width = '0%';
  uploadPct.textContent = '0%';
  uploadStats.textContent = 'startet …';

  const file = selectedFile;
  const passwordsValue = passwordsEl.value;
  const uploadStartedAt = Date.now();
  let lastLoaded = 0;
  let lastTickAt = uploadStartedAt;
  let lastSpeed = 0;

  const upload = new tus.Upload(file, {
    endpoint: '/api/tus',
    // Cookie-Fallback: viele Reverse-Proxy- und Tunnel-Setups (kein TLS,
    // unterschiedliche Origin-Wahrnehmung im Browser) lassen das Session-
    // Cookie verschwinden. Wir senden die sid zusätzlich als X-Session-Id-
    // Header, der Server akzeptiert beides.
    withCredentials: true,
    credentials: 'same-origin',
    headers: SID ? { 'X-Session-Id': SID } : {},
    chunkSize: 16 * 1024 * 1024, // 16 MiB
    retryDelays: [0, 1000, 3000, 5000, 10000],
    metadata: {
      filename: file.name,
      filetype: file.type || 'application/octet-stream',
    },
    onProgress(bytesSent: number, bytesTotal: number) {
      const pct = bytesTotal > 0 ? (bytesSent / bytesTotal) * 100 : 0;
      uploadBar.style.width = pct + '%';
      uploadPct.textContent = pct.toFixed(1) + ' %';

      const now = Date.now();
      const dt = (now - lastTickAt) / 1000;
      if (dt > 0.25) {
        const instSpeed = (bytesSent - lastLoaded) / dt;
        lastSpeed = lastSpeed === 0 ? instSpeed : lastSpeed * 0.6 + instSpeed * 0.4;
        lastLoaded = bytesSent;
        lastTickAt = now;
      }
      const remaining = lastSpeed > 0 ? (bytesTotal - bytesSent) / lastSpeed : null;
      uploadStats.textContent =
        `${fmtBytes(bytesSent)} von ${fmtBytes(bytesTotal)}` +
        (lastSpeed > 0 ? ` · ${fmtBytes(lastSpeed)}/s` : '') +
        (remaining != null && isFinite(remaining) ? ` · noch ${fmtDuration(remaining * 1000)}` : '');
    },
    onError(err: Error) {
      uploadInProgress = false;
      tusUpload = null;
      cancelUploadBtn.hidden = true;
      uploadProgressBlock.hidden = true;
      submitBtn.disabled = !selectedFile;
      toast('Upload-Fehler: ' + err.message, 'error');
    },
    async onSuccess() {
      uploadInProgress = false;
      tusUpload = null;
      cancelUploadBtn.hidden = true;
      uploadProgressBlock.hidden = true;

      // POST /api/jobs to enqueue the analysis job
      try {
        const res = await authedFetch('/api/jobs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ passwords: passwordsValue }),
        });
        if (!res.ok) {
          const j = await res.json().catch(() => ({ error: 'Unbekannter Fehler' }));
          toast((j as { error?: string }).error ?? `Auftrag konnte nicht eingereiht werden (HTTP ${res.status})`, 'error');
          submitBtn.disabled = !selectedFile;
        } else {
          // SSE will update state; clear file selection for next use
          setFile(null);
        }
      } catch (fetchErr) {
        toast('Netzwerkfehler beim Einreihen des Auftrags.', 'error');
        submitBtn.disabled = !selectedFile;
      }
    },
  });

  tusUpload = upload;

  // Resume previous upload if available
  try {
    const previous = await upload.findPreviousUploads();
    if (previous.length > 0) {
      upload.resumeFromPreviousUpload(previous[0]);
    }
  } catch (_) {
    // Ignore — just start fresh
  }

  upload.start();
});

cancelUploadBtn.addEventListener('click', async () => {
  if (tusUpload) {
    await tusUpload.abort();
    tusUpload = null;
  }
  uploadInProgress = false;
  cancelUploadBtn.hidden = true;
  uploadProgressBlock.hidden = true;
  submitBtn.disabled = !selectedFile;
  toast('Upload abgebrochen.');
});

// ─────────────────────────────────────────────
// Cancel job button
// ─────────────────────────────────────────────
cancelJobBtn.addEventListener('click', async () => {
  cancelJobBtn.disabled = true;
  try {
    const r = await authedFetch('/api/cancel', { method: 'POST' });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      toast((j as { error?: string }).error ?? 'Konnte nicht abbrechen.', 'error');
    } else {
      toast('Prozess wird gestoppt …');
    }
  } finally {
    cancelJobBtn.disabled = false;
  }
});

// ─────────────────────────────────────────────
// Reset / new session button
// ─────────────────────────────────────────────
resetBtn.addEventListener('click', async () => {
  await authedFetch('/api/reset', { method: 'POST' }).catch(() => {});
  location.reload();
});

// ─────────────────────────────────────────────
// SSE event processing
// ─────────────────────────────────────────────
let es: EventSource | null = null;

function connectEvents(): void {
  if (es) { try { es.close(); } catch (_) {} }
  // withCredentials versucht das Cookie mitzusenden. Wenn das Setup das
  // Cookie verschluckt, hängen wir die sid zusätzlich als Query-Parameter
  // an — EventSource erlaubt keine custom Headers.
  es = new EventSource(withSid('/api/events'), { withCredentials: true });

  es.addEventListener('state', (ev: MessageEvent) => {
    const snap: SessionSnapshot = JSON.parse(ev.data);
    applySnapshot(snap);
  });

  es.addEventListener('log', (ev: MessageEvent) => {
    const data: { jobId: string; entry: LogEntry } = JSON.parse(ev.data);
    // Only append if for the currently active job
    if (data.jobId === activeJobId) {
      appendActiveLog([data.entry]);
    }
  });

  es.addEventListener('log-replay', (ev: MessageEvent) => {
    const data: { jobId: string; log: LogEntry[] } = JSON.parse(ev.data);
    if (data.jobId === activeJobId) {
      clearActiveLog();
      appendActiveLog(data.log);
    }
  });

  es.addEventListener('outputs', (ev: MessageEvent) => {
    // Outputs arrive for a specific job; we re-render history to reflect new files
    const data: { jobId: string; files: OutputFile[] } = JSON.parse(ev.data);
    // Find the card and update it if present
    const li = jobCardMap.get(data.jobId);
    if (li) {
      // We need the full snapshot to re-render; store partial outputs
      // The next `state` event will carry the full snapshot — we just
      // update the outputs portion directly here for immediacy.
      const dlList = li.querySelector<HTMLUListElement>('.job-downloads');
      const detailDiv = li.querySelector<HTMLDivElement>('.job-card-detail');
      if (detailDiv) {
        const outputsHtml = data.files.map((f) =>
          `<li class="dl-item">
            <div class="dl-name">${escapeHtml(f.name)}</div>
            <div class="filesize">${fmtBytes(f.size)}</div>
            <a href="/api/download/${encodeURIComponent(data.jobId)}/${encodeURIComponent(f.name)}"
               download="${escapeHtml(f.name)}"
               class="dl-btn">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>Download
            </a>
          </li>`
        ).join('');
        if (dlList) {
          dlList.innerHTML = outputsHtml;
        } else if (outputsHtml) {
          const noFilesP = detailDiv.querySelector('p');
          if (noFilesP) noFilesP.remove();
          const ul = document.createElement('ul');
          ul.className = 'downloads job-downloads';
          ul.innerHTML = outputsHtml;
          detailDiv.appendChild(ul);
        }
      }
    }
  });

  es.addEventListener('phase', (ev: MessageEvent) => {
    const data: { jobId: string; phase: string; progress: number | null } = JSON.parse(ev.data);
    if (data.jobId === activeJobId) {
      renderProgress(data.phase, data.progress);
    }
  });

  es.addEventListener('closed', () => {
    try { es?.close(); } catch (_) {}
    es = null;
  });

  // Browser auto-reconnects on error; no special handling needed.
}

// ─────────────────────────────────────────────
// Apply full session snapshot
// ─────────────────────────────────────────────
function applySnapshot(snap: SessionSnapshot): void {
  // Session pill
  sessionPill.textContent = 'Sitzung ' + (snap.sessionId ? snap.sessionId.slice(0, 8) : '?');
  sessionPill.title = 'Sitzung ' + snap.sessionId + '\ngestartet ' + fmtClock(snap.sessionStartedAt);

  // Determine the active job (running or queued)
  const currentJob = snap.currentJobId
    ? snap.jobs.find((j) => j.id === snap.currentJobId) ?? null
    : null;

  // Active-job panel
  renderActiveJob(currentJob);

  // If a job just transitioned to a terminal state and it was our activeJobId, clear it
  if (currentJob === null && activeJobId !== null) {
    // Keep activeJobId so final logs can still arrive, but hide panel
    // (renderActiveJob already hid it above)
  }

  // Job history — show all terminal jobs (not currently running/queued)
  const historyJobs = snap.jobs.filter(
    (j) => j.state !== 'queued' && j.state !== 'running'
  );
  renderJobHistory(historyJobs);
}

// ─────────────────────────────────────────────
// pagehide cleanup
// ─────────────────────────────────────────────
window.addEventListener('pagehide', () => {
  navigator.sendBeacon('/api/reset', '');
});

// ─────────────────────────────────────────────
// Boot
// ─────────────────────────────────────────────
connectEvents();
