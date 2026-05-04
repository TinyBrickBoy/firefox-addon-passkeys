const $ = id => document.getElementById(id);

const loadingEl = $('loading');
const emptyEl   = $('empty');
const listEl    = $('list');
const dialogEl  = $('dialog');
const dialogMsg = $('dialog-msg');

let pendingId = null;

function fmt(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

function render(passkeys) {
  loadingEl.classList.add('hidden');

  if (!passkeys?.length) {
    emptyEl.classList.remove('hidden');
    return;
  }

  listEl.classList.remove('hidden');
  listEl.innerHTML = '';

  passkeys.forEach(pk => {
    const user = pk.userDisplayName || pk.userName || '–';
    const name = pk.rpName || pk.rpId;
    const meta = [fmt(pk.created), pk.counter ? `${pk.counter}× genutzt` : ''].filter(Boolean).join(' · ');

    const li = document.createElement('li');
    li.className = 'item';
    const body = document.createElement('div');
    body.className = 'item-body';

    const siteEl = document.createElement('div');
    siteEl.className = 'item-site';
    siteEl.title = pk.rpId;
    siteEl.textContent = name;
    body.appendChild(siteEl);

    const userEl = document.createElement('div');
    userEl.className = 'item-user';
    userEl.textContent = user;
    body.appendChild(userEl);

    if (meta) {
      const metaEl = document.createElement('div');
      metaEl.className = 'item-meta';
      metaEl.textContent = meta;
      body.appendChild(metaEl);
    }

    const delBtn = document.createElement('button');
    delBtn.className = 'btn-del';
    delBtn.title = 'Löschen';
    delBtn.textContent = '✕';

    li.appendChild(body);
    li.appendChild(delBtn);

    delBtn.onclick = () => {
      pendingId = pk.credentialId;
      dialogMsg.textContent = `Passkey für „${name}" (${user}) wird unwiderruflich gelöscht.`;
      dialogEl.classList.remove('hidden');
    };

    listEl.appendChild(li);
  });
}

$('btn-cancel').onclick = () => { pendingId = null; dialogEl.classList.add('hidden'); };

$('btn-confirm').onclick = async () => {
  if (!pendingId) return;
  const id = pendingId;
  pendingId = null;
  dialogEl.classList.add('hidden');
  await browser.runtime.sendMessage({ action: 'delete-passkey', credentialId: id });
  load();
};

async function load() {
  loadingEl.classList.remove('hidden');
  listEl.classList.add('hidden');
  emptyEl.classList.add('hidden');
  const { passkeys } = await browser.runtime.sendMessage({ action: 'list-passkeys' });
  render(passkeys);
}

// ─── Einstellungen / Nextcloud Sync ──────────────────────────────────────────
const settingsEl = $('settings');
const statusEl   = $('sync-status');
const ncUrl      = $('nc-url');
const ncUser     = $('nc-user');
const ncPass     = $('nc-pass');
const ncPath     = $('nc-path');
const ncPhrase   = $('nc-phrase');
const exportBtn  = $('btn-export');
const importBtn  = $('btn-import');
const saveBtn    = $('btn-save');

function setStatus(msg, kind) {
  statusEl.textContent = msg || '';
  statusEl.className = 'sync-status' + (kind ? ' ' + kind : '');
}

async function openSettings() {
  setStatus('');
  const { config } = await browser.runtime.sendMessage({ action: 'nextcloud-get-config' });
  if (config) {
    ncUrl.value    = config.url || '';
    ncUser.value   = config.username || '';
    ncPass.value   = config.password || '';
    ncPath.value   = config.path || 'passkeys.json';
    ncPhrase.value = config.passphrase || '';
  }
  settingsEl.classList.remove('hidden');
}

function closeSettings() {
  settingsEl.classList.add('hidden');
  setStatus('');
}

function readConfig() {
  return {
    url:        ncUrl.value.trim(),
    username:   ncUser.value.trim(),
    password:   ncPass.value,
    path:       ncPath.value.trim() || 'passkeys.json',
    passphrase: ncPhrase.value,
  };
}

async function saveConfig() {
  await browser.runtime.sendMessage({ action: 'nextcloud-set-config', config: readConfig() });
}

$('btn-settings').onclick = openSettings;
$('btn-back').onclick     = closeSettings;

$('settings-form').addEventListener('submit', async e => {
  e.preventDefault();
  await saveConfig();
  setStatus('Einstellungen gespeichert.', 'ok');
});

async function withBusy(btn, label, fn) {
  const orig = btn.textContent;
  btn.disabled = true;
  exportBtn.disabled = true;
  importBtn.disabled = true;
  saveBtn.disabled = true;
  btn.textContent = label;
  setStatus('');
  try {
    await fn();
  } finally {
    btn.textContent = orig;
    btn.disabled = false;
    exportBtn.disabled = false;
    importBtn.disabled = false;
    saveBtn.disabled = false;
  }
}

exportBtn.onclick = () => withBusy(exportBtn, 'Lade hoch …', async () => {
  await saveConfig();
  const res = await browser.runtime.sendMessage({ action: 'nextcloud-export' });
  if (res.error) {
    setStatus('Fehler: ' + res.error.message, 'err');
  } else {
    const enc = res.encrypted ? ' (verschlüsselt)' : '';
    setStatus(`${res.count} Passkey(s) exportiert${enc}.`, 'ok');
  }
});

importBtn.onclick = () => withBusy(importBtn, 'Lade herunter …', async () => {
  await saveConfig();
  const res = await browser.runtime.sendMessage({ action: 'nextcloud-import', mode: 'merge' });
  if (res.error) {
    setStatus('Fehler: ' + res.error.message, 'err');
  } else {
    setStatus(`${res.added} neu, ${res.total} im Backup.`, 'ok');
    load();
  }
});

load();
