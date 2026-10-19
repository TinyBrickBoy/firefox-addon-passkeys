const $ = id => document.getElementById(id);
const t = (key, ...subs) => browser.i18n.getMessage(key, subs.map(String));

document.documentElement.lang = browser.i18n.getUILanguage();
document.querySelectorAll('[data-i18n]').forEach(node => {
  node.textContent = t(node.dataset.i18n);
});

const MIN_PASSWORD_LENGTH = 8;

function cryptoErrorMessage(err) {
  if (err.code === 'wrong-password') return t('backupErrorWrongPassword');
  if (err.code === 'invalid') return t('backupErrorInvalidFile');
  return err.message || String(err);
}

// ─── Anzeige ──────────────────────────────────────────────────────────────────

function setStatus(el, text, kind) {
  el.textContent = text;
  el.className = 'status' + (kind ? ' ' + kind : '');
}

async function updateExportHint() {
  const { passkeys } = await browser.runtime.sendMessage({ action: 'list-passkeys' });
  $('export-hint').textContent = t('backupExportHint', passkeys.length);
}

function download(filename, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ─── Export ───────────────────────────────────────────────────────────────────

$('export-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const status = $('export-status');
  const password = $('export-password').value;
  const button = e.submitter;

  if (password.length < MIN_PASSWORD_LENGTH) {
    setStatus(status, t('backupErrorPasswordShort', MIN_PASSWORD_LENGTH), 'error');
    return;
  }
  if (password !== $('export-password-confirm').value) {
    setStatus(status, t('backupErrorPasswordMismatch'), 'error');
    return;
  }

  button.disabled = true;
  try {
    const { passkeys } = await browser.runtime.sendMessage({ action: 'list-passkeys' });
    if (!passkeys.length) {
      setStatus(status, t('backupErrorNoPasskeys'), 'error');
      return;
    }
    const backup = await BackupCrypto.encrypt({ passkeys, deleted: [] }, password);
    const date = new Date().toISOString().slice(0, 10);
    download(`passkeys-backup-${date}.json`, JSON.stringify(backup, null, 2));
    e.target.reset();
    setStatus(status, t('backupExportDone', passkeys.length), 'ok');
  } catch (err) {
    setStatus(status, err.message || String(err), 'error');
  } finally {
    button.disabled = false;
  }
});

// ─── Import ───────────────────────────────────────────────────────────────────

$('import-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const status = $('import-status');
  const file = $('import-file').files[0];
  const button = e.submitter;

  if (!file) {
    setStatus(status, t('backupErrorNoFile'), 'error');
    return;
  }

  button.disabled = true;
  try {
    let backup;
    try {
      backup = JSON.parse(await file.text());
    } catch (err) {
      throw new Error(t('backupErrorInvalidFile'));
    }
    let passkeys;
    try {
      ({ payload: { passkeys } } = await BackupCrypto.decrypt(backup, $('import-password').value));
    } catch (err) {
      throw new Error(cryptoErrorMessage(err));
    }
    const result = await browser.runtime.sendMessage({ action: 'import-passkeys', passkeys });
    if (result.error) throw new Error(result.error);
    e.target.reset();
    setStatus(status, t('backupImportDone', result.added, result.updated, result.skipped), 'ok');
    updateExportHint();
  } catch (err) {
    setStatus(status, err.message || String(err), 'error');
  } finally {
    button.disabled = false;
  }
});

// ─── Nextcloud-Sync ───────────────────────────────────────────────────────────

function fmtTime(iso) {
  return new Date(iso).toLocaleString(browser.i18n.getUILanguage(), { dateStyle: 'short', timeStyle: 'short' });
}

/** Zeigt die aktuellen Nextcloud-Sync-Einstellungen im Formular an. */
function renderSync(settings) {
  const enabled = settings.enabled;
  $('sync-server').value = settings.serverUrl;
  $('sync-username').value = settings.username;
  $('sync-folder').value = settings.folder;
  $('sync-app-password').value = '';
  $('sync-password').value = '';
  $('sync-app-password').placeholder = settings.hasAppPassword ? t('syncSavedPlaceholder') : '';
  $('sync-password').placeholder = settings.hasPassword ? t('syncSavedPlaceholder') : '';
  $('sync-app-password').required = !settings.hasAppPassword;
  $('sync-password').required = !settings.hasPassword;
  $('sync-now').classList.toggle('hidden', !enabled);
  $('sync-disable').classList.toggle('hidden', !enabled);
  renderSyncState($('sync-state'), settings);
}

/** Aktualisiert die Statusanzeige (stateEl) anhand von settings.state. */
function renderSyncState(stateEl, settings) {
  const enabled = settings.enabled;
  const state = settings.state || {};
  if (!enabled) {
    stateEl.textContent = t('syncStateOff');
    stateEl.className = 'sync-state';
  } else if (state.lastError) {
    stateEl.textContent = t('syncStateError', state.lastError);
    stateEl.className = 'sync-state error';
  } else if (state.lastSync) {
    stateEl.textContent = t('syncStateOk', fmtTime(state.lastSync));
    stateEl.className = 'sync-state ok';
  } else {
    stateEl.textContent = t('syncStatePending');
    stateEl.className = 'sync-state';
  }
}

/** Führt eine Sync-Aktion aus, zeigt den Status an und rendert das Ergebnis. */
async function syncAction(button, message, status = $('sync-status'), render = renderSync) {
  button.disabled = true;
  setStatus(status, t('syncRunning'));
  try {
    const settings = await browser.runtime.sendMessage(message);
    render(settings);
    setStatus(status, '');
    updateExportHint();
  } catch (err) {
    setStatus(status, err.message || String(err), 'error');
  } finally {
    button.disabled = false;
  }
}

$('sync-form').addEventListener('submit', (e) => {
  e.preventDefault();
  syncAction(e.submitter, {
    action: 'sync-save-settings',
    settings: {
      serverUrl: $('sync-server').value,
      username: $('sync-username').value,
      appPassword: $('sync-app-password').value,
      folder: $('sync-folder').value,
      password: $('sync-password').value,
    },
  });
});

$('sync-now').onclick = (e) => syncAction(e.currentTarget, { action: 'sync-now' });
$('sync-disable').onclick = (e) => syncAction(e.currentTarget, { action: 'sync-disable' });

browser.runtime.sendMessage({ action: 'sync-get-settings' }).then(renderSync);

// ─── Firefox Sync ─────────────────────────────────────────────────────────────

/** Zeigt die aktuellen Firefox-Sync-Einstellungen im Formular an. */
function renderFxSync(settings) {
  const enabled = settings.enabled;
  $('fxsync-password').value = '';
  $('fxsync-password').placeholder = settings.hasPassword ? t('syncSavedPlaceholder') : '';
  $('fxsync-password').required = !settings.hasPassword;
  $('fxsync-now').classList.toggle('hidden', !enabled);
  $('fxsync-disable').classList.toggle('hidden', !enabled);
  renderSyncState($('fxsync-state'), settings);
}

/** syncAction mit den Feldern/dem Renderer der Firefox-Sync-Sektion. */
const fxSyncAction = (button, message) => syncAction(button, message, $('fxsync-status'), renderFxSync);

$('fxsync-form').addEventListener('submit', (e) => {
  e.preventDefault();
  fxSyncAction(e.submitter, {
    action: 'fxsync-save-settings',
    settings: { password: $('fxsync-password').value },
  });
});

$('fxsync-now').onclick = (e) => fxSyncAction(e.currentTarget, { action: 'fxsync-now' });
$('fxsync-disable').onclick = (e) => fxSyncAction(e.currentTarget, { action: 'fxsync-disable' });

browser.runtime.sendMessage({ action: 'fxsync-get-settings' }).then(renderFxSync);
updateExportHint();
