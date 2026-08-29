(() => {
  'use strict';

  const CHUNK_BYTES = 8 * 1024 * 1024;
  const MAX_BROWSER_CONCURRENCY = 4;
  const MAX_AUTOMATIC_RETRIES = 3;
  const MUTATING_METHODS = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);

  const elements = {
    loading: document.getElementById('loadingPanel'),
    closed: document.getElementById('closedPanel'),
    closedTitle: document.getElementById('closedTitle'),
    closedMessage: document.getElementById('closedMessage'),
    unlock: document.getElementById('unlockPanel'),
    unlockForm: document.getElementById('unlockForm'),
    unlockButton: document.getElementById('unlockButton'),
    unlockError: document.getElementById('unlockError'),
    password: document.getElementById('password'),
    uploader: document.getElementById('uploader'),
    inviteTitle: document.getElementById('inviteTitle'),
    profileBadge: document.getElementById('profileBadge'),
    policyTypes: document.getElementById('policyTypes'),
    policyFileSize: document.getElementById('policyFileSize'),
    policyFileCount: document.getElementById('policyFileCount'),
    policyQuota: document.getElementById('policyQuota'),
    policyExpiry: document.getElementById('policyExpiry'),
    fileInput: document.getElementById('fileInput'),
    dropZone: document.getElementById('dropZone'),
    pickerHint: document.getElementById('pickerHint'),
    queueSection: document.getElementById('queueSection'),
    queueSummary: document.getElementById('queueSummary'),
    uploadList: document.getElementById('uploadList'),
    clearFinished: document.getElementById('clearFinishedButton'),
    resumeNotice: document.getElementById('resumeNotice'),
    resumeText: document.getElementById('resumeText'),
    resumePick: document.getElementById('resumePickButton'),
    toastRegion: document.getElementById('toastRegion'),
  };

  const pathParts = window.location.pathname.split('/').filter(Boolean);
  const tokenCandidate = pathParts.length === 3 && pathParts[0] === 'drop' && pathParts[1] === 'i'
    ? pathParts[2]
    : '';
  const token = /^[A-Za-z0-9_-]{20,160}$/.test(tokenCandidate) ? tokenCandidate : null;

  let policy = null;
  let concurrency = 1;
  let activeCount = 0;
  let scheduling = false;
  let toastTimer = null;
  let resumeStorage = null;
  let persistRevision = 0;
  const items = [];
  let savedResumes = [];

  class HttpError extends Error {
    constructor(response, body = null) {
      super(body && typeof body.error === 'string' ? body.error : `Request failed (${response.status})`);
      this.name = 'HttpError';
      this.status = response.status;
      this.body = body;
      this.retryAfter = parseRetryAfter(response.headers.get('Retry-After'));
    }
  }

  function csrfToken() {
    const prefix = 'drop-csrf=';
    for (const value of document.cookie.split(';')) {
      const cookie = value.trim();
      if (cookie.startsWith(prefix)) {
        try { return decodeURIComponent(cookie.slice(prefix.length)); } catch { return ''; }
      }
    }
    return '';
  }

  async function apiFetch(url, options = {}) {
    const method = String(options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    if (MUTATING_METHODS.has(method)) {
      const csrf = csrfToken();
      if (!csrf) throw new Error('The secure session is missing. Reload this page and try again.');
      headers.set('X-Drop-CSRF', csrf);
    }
    return fetch(url, {
      ...options,
      method,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
  }

  async function responseBody(response) {
    const type = response.headers.get('Content-Type') || '';
    if (!type.toLowerCase().includes('application/json')) return null;
    try { return await response.json(); } catch { return null; }
  }

  function policyUrl() {
    return `/drop/api/invites/${encodeURIComponent(token)}/policy`;
  }

  function uploadsUrl() {
    return `/drop/api/invites/${encodeURIComponent(token)}/uploads`;
  }

  async function resumeStorageContext() {
    if (resumeStorage) return resumeStorage;
    const csrf = csrfToken();
    if (!token || !csrf || !window.crypto || !window.crypto.subtle) {
      throw new Error('Private resume storage is unavailable.');
    }
    const encoder = new TextEncoder();
    const tokenDigest = new Uint8Array(await window.crypto.subtle.digest('SHA-256', encoder.encode(token)));
    const keyDigest = await window.crypto.subtle.digest(
      'SHA-256', encoder.encode(`immich-drop-resume-v1\u0000${token}\u0000${csrf}`),
    );
    const key = await window.crypto.subtle.importKey('raw', keyDigest, 'AES-GCM', false, ['encrypt', 'decrypt']);
    try {
      // v0.1.0 briefly used the raw token and plaintext metadata. Never migrate
      // that record: discard it as soon as this invitation is opened again.
      localStorage.removeItem(`sovereign-drop:resume:${token}`);
    } catch { /* Private browsing may disable local storage entirely. */ }
    resumeStorage = {
      name: `sovereign-drop:resume:v1:${base64Url(tokenDigest)}`,
      key,
    };
    return resumeStorage;
  }

  function base64Url(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return window.btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  }

  function base64Bytes(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return window.btoa(binary);
  }

  function decodeBase64(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error('Invalid private resume record.');
    const binary = window.atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  async function encryptResumeRecords(records) {
    const context = await resumeStorageContext();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(records));
    const ciphertext = new Uint8Array(await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, context.key, plaintext));
    return { context, value: JSON.stringify({ v: 1, iv: base64Bytes(iv), data: base64Bytes(ciphertext) }) };
  }

  async function decryptResumeRecords(value) {
    const context = await resumeStorageContext();
    const envelope = JSON.parse(value);
    if (!envelope || envelope.v !== 1) throw new Error('Unsupported private resume record.');
    const iv = decodeBase64(envelope.iv);
    if (iv.length !== 12) throw new Error('Invalid private resume record.');
    const plaintext = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, context.key, decodeBase64(envelope.data),
    );
    return { context, records: JSON.parse(new TextDecoder().decode(plaintext)) };
  }

  function showOnly(panel) {
    elements.loading.hidden = panel !== elements.loading;
    elements.closed.hidden = panel !== elements.closed;
    elements.unlock.hidden = panel !== elements.unlock;
    elements.uploader.hidden = panel !== elements.uploader;
  }

  function showClosed(title, message) {
    elements.closedTitle.textContent = title;
    elements.closedMessage.textContent = message;
    showOnly(elements.closed);
  }

  function showToast(message) {
    window.clearTimeout(toastTimer);
    elements.toastRegion.replaceChildren();
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    elements.toastRegion.append(toast);
    toastTimer = window.setTimeout(() => elements.toastRegion.replaceChildren(), 4500);
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0) return '—';
    if (bytes === 0) return '0 bytes';
    const units = ['bytes', 'KiB', 'MiB', 'GiB', 'TiB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / (1024 ** index);
    const digits = index === 0 ? 0 : value >= 10 ? 0 : 1;
    return `${value.toFixed(digits)} ${units[index]}`;
  }

  function formatDate(value) {
    if (!value) return 'No expiry';
    const normalized = typeof value === 'number' && value < 1_000_000_000_000 ? value * 1000 : value;
    const date = new Date(normalized);
    if (Number.isNaN(date.getTime())) return '—';
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(date);
  }

  function profileLabel(profile) {
    const labels = {
      photos: 'Photos only',
      videos: 'Videos only',
      both: 'Photos and videos',
      live: 'Photos and Live Photos',
    };
    return labels[String(profile || '').toLowerCase()] || 'Selected media';
  }

  function validatePolicy(value) {
    if (!value || typeof value !== 'object') throw new Error('Invalid invitation policy.');
    const allowedExtensions = Array.isArray(value.allowedExtensions)
      ? value.allowedExtensions
          .filter((entry) => typeof entry === 'string')
          .map((entry) => entry.toLowerCase().trim())
          .map((entry) => entry.startsWith('.') ? entry : `.${entry}`)
          .filter((entry) => /^\.[a-z0-9]{1,12}$/.test(entry))
      : [];
    const maxFileBytes = positiveInteger(value.maxFileBytes);
    const maxFiles = positiveInteger(value.maxFiles);
    const quotaBytes = positiveInteger(value.quotaBytes);
    const chunkBytes = positiveInteger(value.chunkBytes);
    const maxClientConcurrency = positiveInteger(value.maxClientConcurrency);
    if (!allowedExtensions.length || !maxFileBytes || !maxFiles || !quotaBytes || chunkBytes !== CHUNK_BYTES || !maxClientConcurrency) {
      throw new Error('This invitation has an unsafe or unsupported upload policy.');
    }
    return {
      label: typeof value.label === 'string' ? value.label.trim().slice(0, 120) : '',
      expiresAt: value.expiresAt || null,
      profile: String(value.profile || '').toLowerCase(),
      allowedExtensions: [...new Set(allowedExtensions)],
      maxFileBytes,
      maxFiles,
      quotaBytes,
      chunkBytes,
      maxClientConcurrency,
    };
  }

  function positiveInteger(value) {
    return Number.isSafeInteger(value) && value > 0 ? value : null;
  }

  async function loadPolicy() {
    if (!token) {
      showClosed('Upload link required', 'Open the complete invitation link sent to you.');
      return;
    }
    try {
      const response = await apiFetch(policyUrl());
      const body = await responseBody(response);
      if (response.status === 401) {
        showOnly(elements.unlock);
        window.setTimeout(() => elements.password.focus(), 0);
        return;
      }
      if (!response.ok) throw new HttpError(response, body);
      policy = validatePolicy(body);
      renderPolicy();
      await restoreResumeRecords();
      showOnly(elements.uploader);
    } catch (error) {
      if (error instanceof HttpError) {
        if (error.status === 404 || error.status === 410) {
          showClosed('This invitation has ended', 'It may have expired, reached its limit, or been closed by the sender.');
        } else if (error.status === 429) {
          showClosed('Too many attempts', 'Please wait a moment before trying this invitation again.');
        } else {
          showClosed('This invitation is unavailable', 'Please try again later or ask the sender for a new link.');
        }
      } else {
        showClosed('Unable to open this invitation', error.message || 'Check your connection and try again.');
      }
    }
  }

  function renderPolicy() {
    const label = policy.label || 'Share your moments';
    elements.inviteTitle.textContent = label;
    document.title = `${label} · Private photo drop`;
    elements.profileBadge.textContent = profileLabel(policy.profile);
    elements.policyTypes.textContent = policy.allowedExtensions.join(', ').toUpperCase();
    elements.policyFileSize.textContent = `Up to ${formatBytes(policy.maxFileBytes)}`;
    elements.policyFileCount.textContent = `Up to ${policy.maxFiles} ${policy.maxFiles === 1 ? 'file' : 'files'}`;
    elements.policyQuota.textContent = formatBytes(policy.quotaBytes);
    elements.policyExpiry.textContent = formatDate(policy.expiresAt);
    elements.fileInput.accept = policy.allowedExtensions.join(',');
    concurrency = Math.max(1, Math.min(policy.maxClientConcurrency, MAX_BROWSER_CONCURRENCY));

    if (policy.profile === 'photos') elements.pickerHint.textContent = 'Choose one or more photos from Photos or Files.';
    if (policy.profile === 'videos') elements.pickerHint.textContent = 'Choose one or more videos from Photos or Files.';
    if (policy.profile === 'live') elements.pickerHint.textContent = 'For Live Photos, select both the image and its matching video when available.';
  }

  elements.unlockForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    elements.unlockError.hidden = true;
    const password = elements.password.value;
    if (!password) {
      elements.unlockError.textContent = 'Enter the password to continue.';
      elements.unlockError.hidden = false;
      elements.password.focus();
      return;
    }
    elements.unlockButton.disabled = true;
    elements.unlockButton.textContent = 'Checking…';
    try {
      const response = await apiFetch(`/drop/api/invites/${encodeURIComponent(token)}/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ password }),
      });
      const body = await responseBody(response);
      if (!response.ok) throw new HttpError(response, body);
      elements.password.value = '';
      showOnly(elements.loading);
      await loadPolicy();
    } catch (error) {
      elements.password.value = '';
      elements.unlockError.textContent = unlockErrorMessage(error);
      elements.unlockError.hidden = false;
      elements.password.focus();
    } finally {
      elements.unlockButton.disabled = false;
      elements.unlockButton.textContent = 'Unlock';
    }
  });

  function unlockErrorMessage(error) {
    if (!(error instanceof HttpError)) return 'Unable to check the password. Check your connection and try again.';
    if (error.status === 401 || error.status === 403) return 'That password is not correct.';
    if (error.status === 410) return 'This invitation has expired or has been closed.';
    if (error.status === 429) return 'Too many attempts. Wait a moment before trying again.';
    return 'Unable to check the password. Please try again.';
  }

  function fileExtension(name) {
    const index = name.lastIndexOf('.');
    return index > 0 ? name.slice(index).toLowerCase() : '';
  }

  function fileKey(fileLike) {
    return `${fileLike.name}\u0000${fileLike.size}\u0000${fileLike.lastModified}`;
  }

  function handleFiles(fileList) {
    if (!policy) return;
    const selected = Array.from(fileList || []);
    if (!selected.length) return;
    let accepted = 0;
    const rejected = [];
    const knownKeys = new Set(items.filter((item) => item.state !== 'cancelled').map((item) => fileKey(item)));
    let currentBytes = items.filter((item) => !['cancelled', 'error'].includes(item.state)).reduce((total, item) => total + item.size, 0);
    let currentCount = items.filter((item) => !['cancelled', 'error'].includes(item.state)).length;

    for (const file of selected) {
      const key = fileKey(file);
      if (knownKeys.has(key)) {
        rejected.push(`${file.name}: already selected`);
        continue;
      }
      if (!policy.allowedExtensions.includes(fileExtension(file.name))) {
        rejected.push(`${file.name}: file type not accepted`);
        continue;
      }
      if (file.size <= 0) {
        rejected.push(`${file.name}: empty file`);
        continue;
      }
      if (file.size > policy.maxFileBytes) {
        rejected.push(`${file.name}: larger than ${formatBytes(policy.maxFileBytes)}`);
        continue;
      }
      if (currentCount + 1 > policy.maxFiles) {
        rejected.push(`${file.name}: invitation file limit reached`);
        continue;
      }
      if (currentBytes + file.size > policy.quotaBytes) {
        rejected.push(`${file.name}: selection exceeds the invitation total limit`);
        continue;
      }

      const resume = savedResumes.find((record) => fileKey(record) === key);
      const item = makeItem(file, resume || null);
      items.push(item);
      knownKeys.add(key);
      currentCount += 1;
      currentBytes += file.size;
      accepted += 1;
    }

    elements.fileInput.value = '';
    if (accepted) {
      persistResumes();
      renderQueue();
      schedule();
    }
    if (rejected.length) {
      const suffix = rejected.length > 1 ? ` and ${rejected.length - 1} more` : '';
      showToast(`${rejected[0]}${suffix}`);
    }
    updateResumeNotice();
  }

  function makeItem(file, resume) {
    return {
      localId: randomLocalId(),
      file,
      name: file.name,
      size: file.size,
      lastModified: file.lastModified,
      uploadId: resume ? resume.uploadId : null,
      uploadUrl: resume ? normalizeUploadUrl(resume.uploadUrl) : null,
      offset: resume && Number.isSafeInteger(resume.offset) ? Math.min(resume.offset, file.size) : 0,
      state: 'queued',
      message: resume ? 'Ready to resume' : 'Waiting',
      controller: null,
      retryCount: 0,
      duplicate: false,
    };
  }

  function randomLocalId() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') return window.crypto.randomUUID();
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  function renderQueue() {
    elements.queueSection.hidden = items.length === 0;
    elements.uploadList.replaceChildren();
    for (const item of items) elements.uploadList.append(renderItem(item));
    renderSummary();
  }

  function renderItem(item) {
    const li = document.createElement('li');
    li.className = 'upload-item';
    li.dataset.itemId = item.localId;

    const top = document.createElement('div');
    top.className = 'item-top';
    const copy = document.createElement('div');
    copy.className = 'file-copy';
    const name = document.createElement('strong');
    name.className = 'file-name';
    name.textContent = item.name;
    name.title = item.name;
    const meta = document.createElement('span');
    meta.className = 'file-meta';
    meta.textContent = formatBytes(item.size);
    const status = document.createElement('span');
    status.className = `file-status${item.state === 'error' ? ' error' : ''}${item.state === 'done' ? ' success' : ''}`;
    status.textContent = statusText(item);
    copy.append(name, meta, status);

    const actions = document.createElement('div');
    actions.className = 'item-actions';
    if (item.state === 'error') {
      actions.append(actionButton('Retry', () => retryItem(item)));
    }
    if (!['done', 'cancelled'].includes(item.state)) {
      actions.append(actionButton('Cancel', () => cancelItem(item), true));
    }
    top.append(copy, actions);

    const track = document.createElement('div');
    track.className = 'progress-track';
    track.setAttribute('role', 'progressbar');
    track.setAttribute('aria-label', `Upload progress for ${item.name}`);
    track.setAttribute('aria-valuemin', '0');
    track.setAttribute('aria-valuemax', '100');
    const percent = item.size ? Math.min(100, Math.floor((item.offset / item.size) * 100)) : 0;
    track.setAttribute('aria-valuenow', String(percent));
    const bar = document.createElement('div');
    bar.className = `progress-bar${item.state === 'error' ? ' error' : ''}`;
    bar.style.width = `${percent}%`;
    track.append(bar);
    li.append(top, track);
    return li;
  }

  function statusText(item) {
    if (item.state === 'uploading') return `${item.message} · ${formatBytes(item.offset)} of ${formatBytes(item.size)}`;
    if (item.state === 'done') return item.duplicate
      ? 'Already received — no additional copy was stored'
      : 'Uploaded successfully';
    if (item.state === 'cancelled') return 'Cancelled';
    return item.message;
  }

  function actionButton(label, handler, danger = false) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `item-action${danger ? ' danger' : ''}`;
    button.textContent = label;
    button.addEventListener('click', handler);
    return button;
  }

  function renderSummary() {
    const uploading = items.filter((item) => item.state === 'uploading').length;
    const waiting = items.filter((item) => item.state === 'queued').length;
    const duplicates = items.filter((item) => item.state === 'done' && item.duplicate).length;
    const done = items.filter((item) => item.state === 'done' && !item.duplicate).length;
    const errors = items.filter((item) => item.state === 'error').length;
    const parts = [];
    if (uploading) parts.push(`${uploading} uploading`);
    if (waiting) parts.push(`${waiting} waiting`);
    if (done) parts.push(`${done} complete`);
    if (duplicates) parts.push(`${duplicates} already received`);
    if (errors) parts.push(`${errors} ${errors === 1 ? 'needs' : 'need'} attention`);
    elements.queueSummary.textContent = parts.join(' · ') || 'No active uploads.';
  }

  function updateItem(item) {
    const old = elements.uploadList.querySelector(`[data-item-id="${CSS.escape(item.localId)}"]`);
    if (old) old.replaceWith(renderItem(item));
    renderSummary();
  }

  function schedule() {
    if (scheduling) return;
    scheduling = true;
    queueMicrotask(() => {
      scheduling = false;
      while (activeCount < concurrency) {
        const next = items.find((item) => item.state === 'queued');
        if (!next) break;
        activeCount += 1;
        next.state = 'uploading';
        next.message = next.offset ? 'Resuming' : 'Preparing';
        updateItem(next);
        runItem(next)
          .catch(() => {})
          .finally(() => {
            activeCount -= 1;
            persistResumes();
            updateResumeNotice();
            schedule();
          });
      }
    });
  }

  async function runItem(item) {
    try {
      if (!item.uploadUrl) await createUpload(item);
      await uploadChunks(item);
      if (item.state === 'cancelled') return;
      item.offset = item.size;
      item.state = 'done';
      item.message = item.duplicate ? 'Already received' : 'Uploaded successfully';
      removeSavedResume(item);
      updateItem(item);
    } catch (error) {
      if (item.state === 'cancelled' || error.name === 'AbortError') return;
      item.state = 'error';
      item.message = uploadErrorMessage(error);
      updateItem(item);
    }
  }

  async function createUpload(item) {
    item.message = 'Creating secure upload';
    updateItem(item);
    // Creation is deliberately not retried automatically: if a response is lost,
    // repeating POST could reserve more than one server-side slot for one file.
    const response = await apiFetch(uploadsUrl(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ name: item.name, size: item.size, lastModified: item.lastModified }),
    });
    const body = await responseBody(response);
    if (!response.ok) throw new HttpError(response, body);
    if (response.status !== 201 || !body || body.chunkBytes !== CHUNK_BYTES) {
      throw new Error('The server returned an unsupported upload session.');
    }
    const url = body.uploadUrl || response.headers.get('Location');
    item.uploadUrl = normalizeUploadUrl(url);
    item.uploadId = typeof body.uploadId === 'string' ? body.uploadId : null;
    item.offset = validOffset(body.offset, item.size);
    if (item.offset !== 0) throw new Error('A new upload started at an invalid offset.');
    persistResumes();
  }

  function normalizeUploadUrl(value) {
    if (typeof value !== 'string' || !value) throw new Error('The server returned an invalid upload address.');
    const parsed = new URL(value, window.location.origin);
    if (parsed.origin !== window.location.origin ||
        !/^\/drop\/api\/uploads\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(parsed.pathname) ||
        parsed.search || parsed.hash) {
      throw new Error('The server returned an invalid upload address.');
    }
    return parsed.pathname;
  }

  async function headUpload(item) {
    const response = await retryRequest(item, () => apiFetch(item.uploadUrl, { method: 'HEAD' }));
    if (!response.ok) throw new HttpError(response);
    const length = headerInteger(response, 'Upload-Length');
    if (length !== item.size) throw new Error('The saved upload no longer matches this file.');
    item.offset = validOffset(headerInteger(response, 'Upload-Offset'), item.size);
    const state = response.headers.get('Upload-State');
    if (state === 'complete' || state === 'duplicate') {
      if (item.offset !== item.size) throw new Error('The server returned an invalid terminal upload offset.');
    }
    if (state === 'duplicate') {
      item.duplicate = true;
    }
    else if (state !== 'receiving' && state !== 'complete') throw new Error('This upload can no longer be resumed.');
    persistResumes();
  }

  async function uploadChunks(item) {
    await headUpload(item);
    while (item.offset < item.size) {
      if (item.state === 'cancelled') return;
      const start = item.offset;
      const chunk = item.file.slice(start, Math.min(start + CHUNK_BYTES, item.size));
      item.message = 'Checking chunk';
      updateItem(item);
      const checksum = await sha256Header(chunk);
      if (item.state === 'cancelled') return;
      item.message = 'Uploading';
      updateItem(item);

      item.controller = new AbortController();
      const response = await retryRequest(item, () => apiFetch(item.uploadUrl, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/offset+octet-stream',
          'Upload-Offset': String(start),
          'Upload-Checksum': checksum,
        },
        body: chunk,
        signal: item.controller.signal,
      }));
      item.controller = null;

      if (response.status === 409) {
        const conflictState = response.headers.get('Upload-State');
        const rawExpected = response.headers.get('Upload-Offset');
        if (rawExpected && /^\d+$/.test(rawExpected)) {
          item.offset = validOffset(Number(rawExpected), item.size);
        } else {
          await headUpload(item);
        }
        if (conflictState === 'complete' || conflictState === 'duplicate') {
          if (item.offset !== item.size) throw new Error('The server returned an invalid terminal upload offset.');
        }
        if (conflictState === 'duplicate') {
          item.duplicate = true;
        }
        persistResumes();
        updateItem(item);
        continue;
      }
      if (!response.ok) throw new HttpError(response, await responseBody(response));
      const acknowledged = validOffset(headerInteger(response, 'Upload-Offset'), item.size);
      if (acknowledged !== start + chunk.size) throw new Error('The server did not acknowledge this chunk exactly.');
      const uploadState = response.headers.get('Upload-State');
      if (uploadState === 'duplicate') {
        if (acknowledged !== item.size) throw new Error('The server returned an invalid duplicate offset.');
        item.duplicate = true;
      }
      else if (acknowledged === item.size && uploadState !== 'complete') {
        throw new Error('The server returned an invalid completed upload state.');
      } else if (acknowledged < item.size && uploadState !== 'receiving') {
        throw new Error('The server returned an invalid upload state.');
      }
      item.offset = acknowledged;
      item.retryCount = 0;
      persistResumes();
      updateItem(item);
    }
  }

  async function retryRequest(item, request) {
    let lastError = null;
    for (let attempt = 0; attempt <= MAX_AUTOMATIC_RETRIES; attempt += 1) {
      if (item.state === 'cancelled') throw new DOMException('Cancelled', 'AbortError');
      try {
        const response = await request();
        if (!shouldRetryResponse(response) || attempt === MAX_AUTOMATIC_RETRIES) return response;
        lastError = new HttpError(response, await responseBody(response));
        const waitSeconds = lastError.retryAfter || Math.min(2 ** attempt, 8);
        item.message = `Server busy · retrying in ${waitSeconds}s`;
        updateItem(item);
        await delay(waitSeconds * 1000, item);
      } catch (error) {
        if (error.name === 'AbortError' || item.state === 'cancelled') throw error;
        lastError = error;
        if (attempt === MAX_AUTOMATIC_RETRIES) throw error;
        const waitSeconds = Math.min(2 ** attempt, 8);
        item.message = `Connection interrupted · retrying in ${waitSeconds}s`;
        updateItem(item);
        await delay(waitSeconds * 1000, item);
      }
    }
    throw lastError || new Error('Upload failed.');
  }

  function shouldRetryResponse(response) {
    return response.status === 429 || response.status === 502 || response.status === 503 || response.status === 504;
  }

  function delay(milliseconds, item) {
    return new Promise((resolve, reject) => {
      const timer = window.setTimeout(resolve, milliseconds);
      const check = window.setInterval(() => {
        if (item.state === 'cancelled') {
          window.clearTimeout(timer);
          window.clearInterval(check);
          reject(new DOMException('Cancelled', 'AbortError'));
        }
      }, 100);
      window.setTimeout(() => window.clearInterval(check), milliseconds + 50);
    });
  }

  function headerInteger(response, name) {
    const raw = response.headers.get(name);
    if (!raw || !/^\d+$/.test(raw)) throw new Error(`The server omitted ${name}.`);
    const value = Number(raw);
    if (!Number.isSafeInteger(value)) throw new Error(`The server returned an invalid ${name}.`);
    return value;
  }

  function validOffset(value, length) {
    if (!Number.isSafeInteger(value) || value < 0 || value > length) throw new Error('The server returned an invalid upload offset.');
    return value;
  }

  async function sha256Header(blob) {
    if (!window.crypto || !window.crypto.subtle) throw new Error('This browser cannot verify upload chunks securely.');
    const digest = new Uint8Array(await window.crypto.subtle.digest('SHA-256', await blob.arrayBuffer()));
    let binary = '';
    for (const byte of digest) binary += String.fromCharCode(byte);
    return `sha256 ${window.btoa(binary)}`;
  }

  function uploadErrorMessage(error) {
    if (!(error instanceof HttpError)) return error.message || 'Upload interrupted. Select Retry to continue.';
    if (error.status === 401 || error.status === 403) return 'This invitation is no longer authorized.';
    if (error.status === 404 || error.status === 410) return 'This invitation or upload has ended.';
    if (error.status === 413) return 'The file or invitation limit was exceeded.';
    if (error.status === 408) return 'This chunk took too long. Select Retry on a better connection.';
    if (error.status === 415) return 'The file contents do not match an accepted media type.';
    if (error.status === 422) return 'The server rejected this file type or name.';
    if (error.status === 429) return 'The service is busy. Select Retry in a moment.';
    if (error.status === 507) return 'The private storage is temporarily full.';
    return 'Upload interrupted. Select Retry to continue.';
  }

  async function cancelItem(item) {
    if (item.state === 'cancelled' || item.state === 'done') return;
    item.state = 'cancelled';
    item.message = 'Cancelled';
    if (item.controller) item.controller.abort();
    updateItem(item);
    if (item.uploadUrl) {
      try {
        await apiFetch(item.uploadUrl, { method: 'DELETE', keepalive: true });
      } catch {
        // The server expires abandoned partial files even if this best-effort request fails.
      }
    }
    removeSavedResume(item);
    persistResumes();
    updateResumeNotice();
    schedule();
  }

  function retryItem(item) {
    if (item.state !== 'error') return;
    item.state = 'queued';
    item.message = item.offset ? 'Ready to resume' : 'Waiting';
    item.retryCount = 0;
    updateItem(item);
    schedule();
  }

  function parseRetryAfter(raw) {
    if (!raw) return null;
    if (/^\d+$/.test(raw)) return Math.max(1, Math.min(Number(raw), 60));
    const time = Date.parse(raw);
    if (Number.isNaN(time)) return null;
    return Math.max(1, Math.min(Math.ceil((time - Date.now()) / 1000), 60));
  }

  function persistResumes() {
    if (!token) return;
    const active = items
      .filter((item) => item.uploadUrl && item.offset < item.size && !['done', 'cancelled'].includes(item.state))
      .map((item) => ({
        uploadId: item.uploadId,
        uploadUrl: item.uploadUrl,
        name: item.name,
        size: item.size,
        lastModified: item.lastModified,
        offset: item.offset,
      }));
    const untouched = savedResumes.filter((record) => !items.some((item) => fileKey(item) === fileKey(record)));
    savedResumes = [...active, ...untouched].slice(0, policy ? policy.maxFiles : 100);
    const revision = ++persistRevision;
    const snapshot = savedResumes.map((record) => ({ ...record }));
    void (async () => {
      try {
        const context = await resumeStorageContext();
        if (revision !== persistRevision) return;
        if (!snapshot.length) {
          localStorage.removeItem(context.name);
          return;
        }
        const encrypted = await encryptResumeRecords(snapshot);
        if (revision === persistRevision) localStorage.setItem(encrypted.context.name, encrypted.value);
      } catch {
        // Resuming after reload is optional when private browsing blocks storage.
      }
    })();
  }

  async function restoreResumeRecords() {
    try {
      const context = await resumeStorageContext();
      const value = localStorage.getItem(context.name);
      if (!value) {
        savedResumes = [];
        updateResumeNotice();
        return;
      }
      const decrypted = await decryptResumeRecords(value);
      savedResumes = Array.isArray(decrypted.records)
        ? decrypted.records.filter(validResumeRecord).slice(0, policy.maxFiles)
        : [];
    } catch {
      savedResumes = [];
    }
    updateResumeNotice();
  }

  function validResumeRecord(record) {
    if (!record || typeof record !== 'object') return false;
    if (typeof record.name !== 'string' || record.name.length < 1 || record.name.length > 255) return false;
    if (!Number.isSafeInteger(record.size) || record.size < 1 || record.size > policy.maxFileBytes) return false;
    if (!Number.isSafeInteger(record.lastModified) || record.lastModified < 0) return false;
    if (!Number.isSafeInteger(record.offset) || record.offset < 0 || record.offset > record.size) return false;
    try { record.uploadUrl = normalizeUploadUrl(record.uploadUrl); } catch { return false; }
    return policy.allowedExtensions.includes(fileExtension(record.name));
  }

  function removeSavedResume(item) {
    savedResumes = savedResumes.filter((record) => fileKey(record) !== fileKey(item));
    persistResumes();
  }

  function updateResumeNotice() {
    const unmatched = savedResumes.filter((record) => !items.some((item) => fileKey(item) === fileKey(record)));
    elements.resumeNotice.hidden = unmatched.length === 0;
    if (unmatched.length) {
      elements.resumeText.textContent = `${unmatched.length} incomplete ${unmatched.length === 1 ? 'upload is' : 'uploads are'} saved in this browser. Reselect the same ${unmatched.length === 1 ? 'file' : 'files'} to continue.`;
    }
  }

  elements.fileInput.addEventListener('change', () => handleFiles(elements.fileInput.files));
  elements.resumePick.addEventListener('click', () => elements.fileInput.click());
  elements.clearFinished.addEventListener('click', () => {
    for (let index = items.length - 1; index >= 0; index -= 1) {
      if (items[index].state === 'done' || items[index].state === 'cancelled') items.splice(index, 1);
    }
    renderQueue();
  });

  for (const eventName of ['dragenter', 'dragover']) {
    elements.dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
      elements.dropZone.classList.add('is-dragging');
    });
  }
  for (const eventName of ['dragleave', 'drop']) {
    elements.dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      elements.dropZone.classList.remove('is-dragging');
    });
  }
  elements.dropZone.addEventListener('drop', (event) => handleFiles(event.dataTransfer.files));

  window.addEventListener('pagehide', persistResumes);
  loadPolicy();
})();
