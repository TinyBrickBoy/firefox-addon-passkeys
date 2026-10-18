// Firefox Sync: hält die Passkeys über das Firefox-Konto auf mehreren PCs gleich.
//
// Die Passkeys liegen verschlüsselt (BackupCrypto) in storage.sync, das Firefox
// mit dem Konto synchronisiert. Ein Eintrag darf dort höchstens 8 KB groß sein,
// darum werden die verschlüsselten Daten auf mehrere Einträge verteilt:
//
//   passkeySync      – Kopf der Datei ohne `data`, dazu { gen, chunks }
//   passkeySync.<i>  – "<gen>:<Teil von data>"
//
// Alles wird mit einem einzigen set() geschrieben. Passen die Teile nicht zu
// `gen`, sind sie vielleicht noch unterwegs, darum wird erst etwas später noch
// einmal gelesen. Passen sie dann immer noch nicht, weil zwei PCs gleichzeitig
// geschrieben haben, überschreibt der Sync den Stand mit dem eigenen. Weil jeder
// PC seine Passkeys lokal behält und beim nächsten Sync wieder zusammenführt,
// geht dabei nichts verloren.
//
// storage.local enthält:
//   fxSyncSettings – { enabled, password }
//   fxSyncState    – { lastSync, lastError }

const FX_SYNC_KEY = 'passkeySync';
const FX_CHUNK_SIZE = 8000;
const FX_SYNC_DELAY_MS = 3000;
const FX_SYNC_RETRY_MS = 60 * 1000;

let fxSyncRunning = null;
let fxSyncAgain = false;
let fxSyncTimer = null;
let fxSyncApplying = false;
let fxSyncLastGen = null;
let fxSyncMixedGen = null;

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
// { mixed: gen }, wenn die Teile nicht zum Kopf passen
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
    if (typeof chunk !== 'string' || !chunk.startsWith(head.gen + ':')) return { mixed: head.gen };
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
    await browser.storage.sync.set(items);
  } catch (err) {
    if (/quota/i.test(String(err && (err.name + ' ' + err.message)))) {
      throw new SyncError('fxSyncErrorQuota');
    }
    throw err;
  }
  // Erst nach dem erfolgreichen Schreiben, sonst wäre der alte Stand unlesbar
  if (stale.length) await browser.storage.sync.remove(stale);
}

async function runFxSync(settings) {
  const remote = await readFxRemote(settings);
  if (remote && remote.mixed && remote.mixed !== fxSyncMixedGen) {
    fxSyncMixedGen = remote.mixed;
    scheduleFxSync(FX_SYNC_RETRY_MS);
    return;
  }
  fxSyncMixedGen = null;
  const usable = remote && !remote.mixed ? remote : null;

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
  // Änderungen während eines laufenden Syncs kommen in einem zweiten Durchlauf mit
  if (fxSyncRunning) {
    fxSyncAgain = true;
    return fxSyncRunning;
  }
  fxSyncAgain = false;
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
  })().finally(() => {
    fxSyncRunning = null;
    if (fxSyncAgain) scheduleFxSync(0);
  });
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
  if (area !== 'sync') return;
  const foreign = Object.entries(changes).some(([key, { newValue }]) => {
    if (key === FX_SYNC_KEY) return !(newValue && newValue.gen === fxSyncLastGen);
    if (!key.startsWith(FX_SYNC_KEY + '.')) return false;
    return typeof newValue === 'string' && !newValue.startsWith(fxSyncLastGen + ':');
  });
  if (foreign) scheduleFxSync();
});

scheduleFxSync(0);
