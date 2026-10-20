// Upgrade-Test: Jede veröffentlichte Version muss sich auf den aktuellen Stand
// aktualisieren lassen, ohne dass Passkeys, Löschungen oder Einstellungen
// verloren gehen.
//
// Für jeden Versions-Tag (und die beiden 1.0.0-Stände ohne Tag) werden die
// Background-Skripte dieser Version aus Git geladen. Mit ihnen werden Passkeys
// angelegt, benutzt und gelöscht. Danach startet der aktuelle Code mit
// denselben Daten und muss mit ihnen anmelden und synchronisieren können.
//
// Aufruf: node tests/upgrade.test.js   (braucht die Git-Tags im Checkout)

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const PASSWORD = 'passwort123';

// 1.0.0 wurde nie getaggt: einmal ohne und einmal mit fester Add-on-ID
const UNTAGGED = ['9985b73', '5ce0bd9'];

const git = (...args) => execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' });

function versions() {
  const tags = git('tag', '-l').split('\n').filter(tag => /^v?\d+\.\d+\.\d+$/.test(tag));
  // Ohne Tags würde der Test nur 1.0.0 prüfen und trotzdem bestehen
  if (tags.length === 0) throw new Error('Keine Versions-Tags gefunden, erst "git fetch --tags" ausführen');
  return [...UNTAGGED, ...tags];
}

function scriptsOf(manifest) {
  return JSON.parse(manifest).background.scripts;
}

function sourcesAt(rev) {
  return scriptsOf(git('show', rev + ':manifest.json')).map(file => ({ file, code: git('show', rev + ':' + file) }));
}

function currentSources() {
  return scriptsOf(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'))
    .map(file => ({ file, code: fs.readFileSync(path.join(ROOT, file), 'utf8') }));
}

// ─── Nachgebauter Browser ─────────────────────────────────────────────────────

function storageArea(data) {
  return {
    async get(keys) {
      if (keys === null) return structuredClone(data.value);
      const out = {};
      for (const key of [].concat(keys)) if (key in data.value) out[key] = structuredClone(data.value[key]);
      return out;
    },
    async set(items) { Object.assign(data.value, structuredClone(items)); },
    async remove(keys) { for (const key of [].concat(keys)) delete data.value[key]; },
  };
}

// Startet die Background-Skripte in einem eigenen Kontext, wie Firefox es tut
function boot(sources, local, sync) {
  const browser = {
    storage: { local: storageArea(local), sync: storageArea(sync), onChanged: { addListener() {} } },
    i18n: { getMessage: key => key },
    runtime: { onMessage: { addListener() {} }, getURL: p => 'moz-extension://test/' + p },
  };
  const ctx = vm.createContext({
    browser, crypto, TextEncoder, TextDecoder, btoa, atob, DOMException, structuredClone,
    unescape, encodeURIComponent,
    console: { log() {}, error() {} },
    setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0,
    fetch: async () => { throw new Error('offline'); },
  });
  // Top-Level-Deklarationen sollen wie in Firefox über alle Skripte sichtbar sein
  const globalize = code => code
    .replace(/^const /gm, 'var ')
    .replace(/^let /gm, 'var ')
    .replace(/^class (\w+)/gm, 'var $1 = class $1');
  for (const { file, code } of sources) vm.runInContext(globalize(code), ctx, { filename: file });
  return ctx;
}

async function settle(ctx) {
  for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve));
  if (ctx.withStorageLock) await ctx.withStorageLock(async () => {});
}

const createOptions = rpId => ({
  rp: { id: rpId },
  user: { id: { __buf: true, data: [1, 2, 3] }, name: 'user@' + rpId, displayName: 'User' },
  challenge: { __buf: true, data: [5, 6] },
});
const getOptions = rpId => ({ rpId, challenge: { __buf: true, data: [7, 8] } });

// Meldet sich an und prüft die Signatur mit dem gespeicherten öffentlichen Schlüssel
async function signsIn(ctx, local, rpId) {
  const result = await ctx.handleGet(getOptions(rpId), 'https://' + rpId, rpId);
  const pk = local.value.passkeys.find(p => p.rpId === rpId);
  const key = await crypto.subtle.importKey(
    'raw', new Uint8Array([4, ...pk.publicKeyX, ...pk.publicKeyY]),
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
  );
  const der = Buffer.from(result.response.signature);
  const rLen = der[3];
  const r = der.subarray(4, 4 + rLen);
  const s = der.subarray(6 + rLen, 6 + rLen + der[5 + rLen]);
  const fixed = b => { b = b[0] === 0 ? b.subarray(1) : b; return Buffer.concat([Buffer.alloc(32 - b.length), b]); };
  const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(result.response.clientDataJSON)));
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' }, key,
    Buffer.concat([fixed(r), fixed(s)]),
    new Uint8Array([...result.response.authenticatorData, ...clientDataHash])
  );
}

// ─── Test ─────────────────────────────────────────────────────────────────────

async function checkUpgrade(rev, current) {
  const local = { value: {} };
  const sync = { value: {} };
  const errors = [];
  const expect = (ok, what) => { if (!ok) errors.push(what); };

  // Mit der alten Version benutzen
  const old = boot(sourcesAt(rev), local, sync);
  for (const rpId of ['a.com', 'b.com', 'c.com']) {
    await old.handleCreate(createOptions(rpId), 'https://' + rpId, rpId);
  }
  await old.handleGet(getOptions('a.com'), 'https://a.com', 'a.com');
  const deletedId = local.value.passkeys.find(p => p.rpId === 'c.com').credentialId;
  await old.deletePasskey(deletedId);
  const hadFxSync = typeof old.saveFxSyncSettings === 'function';
  if (hadFxSync) await old.saveFxSyncSettings({ password: PASSWORD });
  await settle(old);

  // Auf den aktuellen Stand aktualisieren
  const upgraded = boot(current, local, sync);
  await settle(upgraded);
  const passkeys = local.value.passkeys;
  expect(passkeys.map(p => p.rpId).sort().join() === 'a.com,b.com', 'Passkeys bleiben erhalten, gelöschte bleiben gelöscht');
  expect(passkeys.every(upgraded.isValidPasskey), 'alle Passkeys sind gültig');
  expect(passkeys.every(p => p.modified), 'alle Passkeys haben modified');
  expect(await signsIn(upgraded, local, 'a.com'), 'Anmelden mit einem benutzten Passkey');
  expect(await signsIn(upgraded, local, 'b.com'), 'Anmelden mit einem unbenutzten Passkey');
  expect(local.value.passkeys.find(p => p.rpId === 'a.com').counter === 2, 'Zähler läuft weiter');

  // Firefox Sync weiterverwenden oder neu einschalten
  if (hadFxSync) await upgraded.fxSyncNow();
  else await upgraded.saveFxSyncSettings({ password: PASSWORD });
  expect(!local.value.fxSyncState.lastError, 'Firefox Sync ohne Fehler: ' + local.value.fxSyncState.lastError);

  // Ein zweiter PC mit dem aktuellen Stand bekommt die Passkeys
  const otherLocal = { value: {} };
  const other = boot(current, otherLocal, sync);
  await settle(other);
  await other.saveFxSyncSettings({ password: PASSWORD });
  const synced = (otherLocal.value.passkeys || []).map(p => p.rpId + ':' + p.counter).sort().join();
  expect(synced === 'a.com:2,b.com:1', 'zweiter PC bekommt die Passkeys, bekam ' + synced);

  // Ein weiterer Start ändert nichts mehr
  const before = JSON.stringify(local.value.passkeys);
  await settle(boot(current, local, sync));
  expect(JSON.stringify(local.value.passkeys) === before, 'Migration läuft nur einmal');

  return errors;
}

(async () => {
  const current = currentSources();
  let failed = false;
  for (const rev of versions()) {
    const errors = await checkUpgrade(rev, current);
    console.log((errors.length ? 'FAIL ' : 'ok   ') + rev + (errors.length ? ': ' + errors.join('; ') : ''));
    failed = failed || errors.length > 0;
  }
  process.exit(failed ? 1 : 0);
})().catch(err => {
  console.error(err);
  process.exit(1);
});
