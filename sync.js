// Nextcloud-Sync: hält die Passkeys auf mehreren PCs gleich.
//
// Die Passkeys liegen verschlüsselt (BackupCrypto) als eine Datei in der
// Nextcloud und werden per WebDAV mit einem App-Passwort gelesen und
// geschrieben. Jeder Sync lädt die Datei, führt sie mit dem lokalen Stand
// zusammen (mergeStores) und lädt das Ergebnis wieder hoch. Ein ETag verhindert,
// dass zwei PCs gleichzeitig schreiben und dabei Änderungen verloren gehen.
//
// storage.local enthält:
//   syncSettings – { enabled, serverUrl, username, appPassword, folder, password }
//   syncState    – { lastSync, lastError }

const SYNC_FILE = 'passkeys-sync.json';
const SYNC_INTERVAL_MS = 15 * 60 * 1000;
const SYNC_DELAY_MS = 3000;

let syncRunning = null;
let syncTimer = null;
let syncApplying = false;

class SyncError extends Error {
  constructor(key, ...subs) {
    super(t(key, ...subs));
  }
}

async function loadSyncSettings() {
  const { syncSettings } = await browser.storage.local.get('syncSettings');
  return syncSettings || null;
}

async function setSyncState(state) {
  await browser.storage.local.set({ syncState: state });
}

// Für die Backup-Seite: ohne App-Passwort und Sync-Passwort
async function getSyncSettings() {
  const { syncSettings, syncState } = await browser.storage.local.get(['syncSettings', 'syncState']);
  const s = syncSettings || {};
  return {
    enabled: !!s.enabled,
    serverUrl: s.serverUrl || '',
    username: s.username || '',
    folder: s.folder || 'Passkeys',
    hasAppPassword: !!s.appPassword,
    hasPassword: !!s.password,
    state: syncState || {},
  };
}

// Leere Passwortfelder behalten das gespeicherte Passwort
async function saveSyncSettings(input) {
  const old = (await loadSyncSettings()) || {};
  let serverUrl = String(input.serverUrl || '').trim().replace(/\/+$/, '');
  if (serverUrl && !/^https?:\/\//i.test(serverUrl)) serverUrl = 'https://' + serverUrl;

  const settings = {
    enabled: true,
    serverUrl,
    username: String(input.username || '').trim(),
    folder: String(input.folder || '').trim().replace(/^\/+|\/+$/g, '') || 'Passkeys',
    appPassword: input.appPassword || old.appPassword || '',
    password: input.password || old.password || '',
  };

  if (!settings.serverUrl || !settings.username || !settings.appPassword) {
    throw new SyncError('syncErrorMissingFields');
  }
  if (settings.password.length < 8) {
    throw new SyncError('backupErrorPasswordShort', 8);
  }

  await browser.storage.local.set({ syncSettings: settings });
  await syncNow();
  return getSyncSettings();
}

async function disableSync() {
  await browser.storage.local.remove(['syncSettings', 'syncState']);
  return getSyncSettings();
}

// ─── WebDAV ──────────────────────────────────────────────────────────────────

function davBase(settings) {
  return settings.serverUrl + '/remote.php/dav/files/' + encodeURIComponent(settings.username);
}

function folderParts(settings) {
  return settings.folder.split('/').filter(Boolean);
}

function fileUrl(settings) {
  return [davBase(settings), ...folderParts(settings).map(encodeURIComponent), SYNC_FILE].join('/');
}

async function dav(settings, method, url, { body, headers } = {}) {
  const auth = btoa(unescape(encodeURIComponent(settings.username + ':' + settings.appPassword)));
  let res;
  try {
    res = await fetch(url, {
      method,
      body,
      // Ohne Cookies, sonst verlangt Nextcloud bei einer offenen Sitzung ein CSRF-Token
      credentials: 'omit',
      cache: 'no-store',
      headers: { Authorization: 'Basic ' + auth, ...headers },
    });
  } catch (err) {
    throw new SyncError('syncErrorNetwork', settings.serverUrl);
  }
  if (res.status === 401 || res.status === 403) throw new SyncError('syncErrorAuth');
  return res;
}

async function ensureFolder(settings) {
  let url = davBase(settings);
  for (const part of folderParts(settings)) {
    url += '/' + encodeURIComponent(part);
    const res = await dav(settings, 'MKCOL', url);
    // 405: Ordner gibt es schon
    if (!res.ok && res.status !== 405) throw new SyncError('syncErrorServer', res.status);
  }
}

// Liefert { store, salt, etag } oder null, wenn es die Datei noch nicht gibt
async function downloadRemote(settings) {
  const res = await dav(settings, 'GET', fileUrl(settings));
  if (res.status === 404) return null;
  if (!res.ok) throw new SyncError('syncErrorServer', res.status);

  let file;
  try {
    file = await res.json();
  } catch (err) {
    throw new SyncError('syncErrorRemoteInvalid');
  }

  try {
    const { payload, salt } = await BackupCrypto.decrypt(file, settings.password);
    return { store: { passkeys: payload.passkeys, deleted: payload.deleted }, salt, etag: res.headers.get('ETag') };
  } catch (err) {
    if (err.code === 'wrong-password') throw new SyncError('syncErrorWrongPassword');
    throw new SyncError('syncErrorRemoteInvalid');
  }
}

// false, wenn ein anderer PC die Datei inzwischen geändert hat
async function uploadRemote(settings, store, remote) {
  const file = await BackupCrypto.encrypt(
    { passkeys: store.passkeys, deleted: store.deleted },
    settings.password,
    remote && remote.salt
  );
  const headers = { 'Content-Type': 'application/json' };
  if (remote && remote.etag) headers['If-Match'] = remote.etag;
  else if (!remote) headers['If-None-Match'] = '*';

  const put = () => dav(settings, 'PUT', fileUrl(settings), { body: JSON.stringify(file), headers });
  let res = await put();
  // 404/409: Ordner fehlt noch
  if (res.status === 404 || res.status === 409) {
    await ensureFolder(settings);
    res = await put();
  }
  if (res.status === 412) return false;
  if (!res.ok) throw new SyncError('syncErrorServer', res.status);
  return true;
}

// Vergleich unabhängig von der Reihenfolge, sonst würden zwei PCs mit gleichem
// Inhalt die Datei bei jedem Sync gegenseitig neu hochladen
function canonical(store) {
  const byId = (a, b) => (a.credentialId < b.credentialId ? -1 : a.credentialId > b.credentialId ? 1 : 0);
  return JSON.stringify({
    passkeys: [...store.passkeys].sort(byId),
    deleted: [...store.deleted].sort(byId),
  });
}
const sameStore = (a, b) => canonical(a) === canonical(b);

async function runSync(settings) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const remote = await downloadRemote(settings);

    const merged = await withStorageLock(async () => {
      const local = await loadStore();
      if (!remote) return local;
      const { store } = mergeStores(local, remote.store);
      if (!sameStore(store, local)) {
        // Eigene Änderung durch den Sync löst keinen weiteren Sync aus
        syncApplying = true;
        try { await saveStore(store); } finally { syncApplying = false; }
      }
      return store;
    });

    if (remote && sameStore(merged, remote.store)) return;
    if (await uploadRemote(settings, merged, remote)) return;
  }
  throw new SyncError('syncErrorConflict');
}

function syncNow() {
  if (syncRunning) return syncRunning;
  syncRunning = (async () => {
    const settings = await loadSyncSettings();
    if (!settings || !settings.enabled) return;
    try {
      await runSync(settings);
      await setSyncState({ lastSync: new Date().toISOString(), lastError: null });
    } catch (err) {
      console.error('[Passkey] Sync FEHLER', err);
      const { syncState } = await browser.storage.local.get('syncState');
      await setSyncState({ lastSync: (syncState && syncState.lastSync) || null, lastError: err.message });
    }
  })().finally(() => { syncRunning = null; });
  return syncRunning;
}

function scheduleSync(delay = SYNC_DELAY_MS) {
  clearTimeout(syncTimer);
  syncTimer = setTimeout(syncNow, delay);
}

/** Wird von saveStore nach jeder lokalen Änderung aufgerufen. */
function onPasskeysChanged() {
  if (!syncApplying) scheduleSync();
  onPasskeysChangedFx();
}

scheduleSync(0);
setInterval(syncNow, SYNC_INTERVAL_MS);
