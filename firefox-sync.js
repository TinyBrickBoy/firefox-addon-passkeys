// Firefox Sync: hält die Passkeys über das Firefox-Konto auf mehreren PCs gleich.
//
// Die Passkeys liegen verschlüsselt (BackupCrypto) in storage.sync, das Firefox
// mit dem Konto synchronisiert. Ein Eintrag darf dort höchstens 8 KB groß sein,
// darum werden die verschlüsselten Daten auf mehrere Einträge verteilt:
//
//   passkeySync      – Kopf der Datei ohne `data`, dazu { gen, chunks }
//   passkeySync.<i>  – "<gen>:<Teil von data>"
//
// Alles wird mit einem einzigen set() geschrieben. Haben zwei PCs gleichzeitig
// geschrieben und passen die Teile nicht mehr zu `gen`, überschreibt der nächste
// Sync den Stand mit dem eigenen. Weil jeder PC seine Passkeys lokal behält und
// beim nächsten Sync wieder zusammenführt, geht dabei nichts verloren.
//
// storage.local enthält:
//   fxSyncSettings – { enabled, password }
//   fxSyncState    – { lastSync, lastError }

const FX_SYNC_KEY = 'passkeySync';
const FX_CHUNK_SIZE = 8000;
const FX_SYNC_DELAY_MS = 3000;

let fxSyncRunning = null;
let fxSyncTimer = null;
let fxSyncApplying = false;
let fxSyncLastGen = null;

async function loadFxSyncSettings() {
  const { fxSyncSettings } = await browser.storage.local.get('fxSyncSettings');
  return fxSyncSettings || null;
}

async function setFxSyncState(state) {
  await browser.storage.local.set({ fxSyncState: state });
}

// Für die Backup-Seite: ohne Sync-Passwort
async function getFxSyncSettings() {
  const { fxSyncSettings, fxSyncState } = await browser.storage.local.get(['fxSyncSettings', 'fxSyncState']);
  const s = fxSyncSettings || {};
  return {
    enabled: !!s.enabled,
    hasPassword: !!s.password,
    state: fxSyncState || {},
  };
}

// Ein leeres Passwortfeld behält das gespeicherte Passwort
async function saveFxSyncSettings(input) {
  const old = (await loadFxSyncSettings()) || {};
  const settings = { enabled: true, password: input.password || old.password || '' };
  if (settings.password.length < 8) {
    throw new SyncError('backupErrorPasswordShort', 8);
  }
  await browser.storage.local.set({ fxSyncSettings: settings });
  await fxSyncNow();
  return getFxSyncSettings();
}

async function disableFxSync() {
  await browser.storage.local.remove(['fxSyncSettings', 'fxSyncState']);
  return getFxSyncSettings();
}

// ─── storage.sync ────────────────────────────────────────────────────────────

const chunkKey = i => FX_SYNC_KEY + '.' + i;

// Liefert { store, salt }, null wenn noch nichts gespeichert ist, oder
// { inconsistent: true }, wenn die Teile von verschiedenen Schreibvorgängen stammen
async function readFxRemote(settings) {
  const all = await browser.storage.sync.get(null);
  const head = all[FX_SYNC_KEY];
  if (!head) return null;
  if (!Number.isInteger(head.chunks) || head.chunks < 0 || typeof head.gen !== 'string') {
    throw new SyncError('fxSyncErrorRemoteInvalid');
  }

  let data = '';
  for (let i = 0; i < head.chunks; i++) {
    const chunk = all[chunkKey(i)];
    if (typeof chunk !== 'string' || !chunk.startsWith(head.gen + ':')) return { inconsistent: true };
    data += chunk.slice(head.gen.length + 1);
  }

  const { gen, chunks, ...file } = head;
  try {
    const { payload, salt } = await BackupCrypto.decrypt({ ...file, data }, settings.password);
    return { store: { passkeys: payload.passkeys, deleted: payload.deleted }, salt };
  } catch (err) {
    if (err.code === 'wrong-password') throw new SyncError('fxSyncErrorWrongPassword');
    throw new SyncError('fxSyncErrorRemoteInvalid');
  }
}

async function writeFxRemote(settings, store, remote) {
  const { data, ...file } = await BackupCrypto.encrypt(
    { passkeys: store.passkeys, deleted: store.deleted },
    settings.password,
    remote && remote.salt
  );
  const gen = base64urlEncode(randomBytes(6));
  const items = {};
  let chunks = 0;
  for (let i = 0; i < data.length; i += FX_CHUNK_SIZE) {
    items[chunkKey(chunks++)] = gen + ':' + data.slice(i, i + FX_CHUNK_SIZE);
  }
  items[FX_SYNC_KEY] = { ...file, gen, chunks };

  const stale = Object.keys(await browser.storage.sync.get(null))
    .filter(key => key.startsWith(FX_SYNC_KEY + '.') && !(key in items));

  // Der eigene Schreibvorgang löst über storage.onChanged keinen weiteren Sync aus
  fxSyncLastGen = gen;
  try {
    // Alte Teile zuerst entfernen, damit der Platz für die neuen reicht
    if (stale.length) await browser.storage.sync.remove(stale);
    await browser.storage.sync.set(items);
  } catch (err) {
    if (/quota/i.test(String(err && (err.name + ' ' + err.message)))) {
      throw new SyncError('fxSyncErrorQuota');
    }
    throw err;
  }
}

async function runFxSync(settings) {
  const remote = await readFxRemote(settings);
  const usable = remote && !remote.inconsistent ? remote : null;

  const merged = await withStorageLock(async () => {
    const local = await loadStore();
    if (!usable) return local;
    const { store } = mergeStores(local, usable.store);
    if (!sameStore(store, local)) {
      // Eigene Änderung durch den Sync löst keinen weiteren Firefox Sync aus
      fxSyncApplying = true;
      try { await saveStore(store); } finally { fxSyncApplying = false; }
    }
    return store;
  });

  if (usable && sameStore(merged, usable.store)) return;
  await writeFxRemote(settings, merged, usable);
}

function fxSyncNow() {
  if (fxSyncRunning) return fxSyncRunning;
  fxSyncRunning = (async () => {
    const settings = await loadFxSyncSettings();
    if (!settings || !settings.enabled) return;
    try {
      await runFxSync(settings);
      await setFxSyncState({ lastSync: new Date().toISOString(), lastError: null });
    } catch (err) {
      console.error('[Passkey] Firefox Sync FEHLER', err);
      const { fxSyncState } = await browser.storage.local.get('fxSyncState');
      await setFxSyncState({ lastSync: (fxSyncState && fxSyncState.lastSync) || null, lastError: err.message });
    }
  })().finally(() => { fxSyncRunning = null; });
  return fxSyncRunning;
}

function scheduleFxSync(delay = FX_SYNC_DELAY_MS) {
  clearTimeout(fxSyncTimer);
  fxSyncTimer = setTimeout(fxSyncNow, delay);
}

// Wird von onPasskeysChanged nach jeder lokalen Änderung aufgerufen
function onPasskeysChangedFx() {
  if (!fxSyncApplying) scheduleFxSync();
}

// Firefox hat Daten von einem anderen PC geholt
browser.storage.onChanged.addListener((changes, area) => {
  const head = area === 'sync' && changes[FX_SYNC_KEY];
  if (head && !(head.newValue && head.newValue.gen === fxSyncLastGen)) scheduleFxSync();
});

scheduleFxSync(0);
