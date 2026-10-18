// Background-Script: Krypto-Operationen und Passkey-Speicherung

const t = (key, ...subs) => browser.i18n.getMessage(key, subs.map(String));

// ─── CBOR Minimal-Encoder ────────────────────────────────────────────────────

function cborEncodeInt(value) {
  if (value >= 0) {
    if (value < 24) return [value];
    if (value < 256) return [0x18, value];
    if (value < 65536) return [0x19, value >> 8, value & 0xff];
    return [0x1a, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
  } else {
    const n = -1 - value;
    if (n < 24) return [0x20 | n];
    if (n < 256) return [0x38, n];
    if (n < 65536) return [0x39, n >> 8, n & 0xff];
    return [0x3a, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  }
}

function cborEncodeBytes(bytes) {
  const len = bytes.length;
  let hdr;
  if (len < 24) hdr = [0x40 | len];
  else if (len < 256) hdr = [0x58, len];
  else hdr = [0x59, len >> 8, len & 0xff];
  return [...hdr, ...bytes];
}

function cborEncodeText(str) {
  const bytes = Array.from(new TextEncoder().encode(str));
  const len = bytes.length;
  let hdr;
  if (len < 24) hdr = [0x60 | len];
  else if (len < 256) hdr = [0x78, len];
  else hdr = [0x79, len >> 8, len & 0xff];
  return [...hdr, ...bytes];
}

function cborEncodeMap(entries) {
  const len = entries.length;
  const hdr = len < 24 ? [0xa0 | len] : [0xb8, len];
  const result = [...hdr];
  for (const [k, v] of entries) {
    result.push(...cborEncode(k));
    result.push(...cborEncode(v));
  }
  return result;
}

function cborEncodeArray(items) {
  const len = items.length;
  const hdr = len < 24 ? [0x80 | len] : [0x98, len];
  const result = [...hdr];
  for (const item of items) result.push(...cborEncode(item));
  return result;
}

function cborEncode(value) {
  if (value === null || value === undefined) return [0xf6];
  if (typeof value === 'number') return cborEncodeInt(Math.trunc(value));
  if (typeof value === 'string') return cborEncodeText(value);
  if (value instanceof Uint8Array) return cborEncodeBytes(Array.from(value));
  if (Array.isArray(value)) {
    // [__map, [[k,v],...]] für geordnete Maps
    if (value[0] === '__map') return cborEncodeMap(value[1]);
    return cborEncodeArray(value);
  }
  return [0xf6];
}

// ─── Hilfsfunktionen ─────────────────────────────────────────────────────────

function arrayToBuffer(arr) {
  return new Uint8Array(arr).buffer;
}

function bufferToArray(buf) {
  return Array.from(new Uint8Array(buf));
}

function deserializeBuffer(val) {
  if (!val) return null;
  if (val.__buf) return new Uint8Array(val.data);
  if (Array.isArray(val)) return new Uint8Array(val);
  return val;
}

function deserializeOptions(opts) {
  return JSON.parse(JSON.stringify(opts), function (key, value) {
    if (value && typeof value === 'object' && value.__buf) {
      return new Uint8Array(value.data);
    }
    return value;
  });
}

function randomBytes(n) {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  return arr;
}

// Reines JS Base64url – kein btoa/atob, kein InvalidCharacterError
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function base64urlEncode(bytes) {
  let out = '';
  const n = bytes.length;
  for (let i = 0; i < n; i += 3) {
    const b0 = bytes[i], b1 = bytes[i + 1] ?? 0, b2 = bytes[i + 2] ?? 0;
    out += B64URL[b0 >> 2];
    out += B64URL[((b0 & 3) << 4) | (b1 >> 4)];
    out += B64URL[((b1 & 15) << 2) | (b2 >> 6)];
    out += B64URL[b2 & 63];
  }
  const rem = n % 3;
  return rem === 1 ? out.slice(0, -2) : rem === 2 ? out.slice(0, -1) : out;
}

function base64urlDecode(str) {
  const lookup = new Uint8Array(128);
  for (let i = 0; i < B64URL.length; i++) lookup[B64URL.charCodeAt(i)] = i;
  lookup['+'.charCodeAt(0)] = 62; lookup['/'.charCodeAt(0)] = 63;
  const pad = (4 - (str.length % 4)) % 4;
  const s = str + '='.repeat(pad);
  const out = [];
  for (let i = 0; i < s.length; i += 4) {
    const a = lookup[s.charCodeAt(i)], b = lookup[s.charCodeAt(i + 1)];
    const c = lookup[s.charCodeAt(i + 2)], d = lookup[s.charCodeAt(i + 3)];
    out.push((a << 2) | (b >> 4));
    if (s[i + 2] !== '=') out.push(((b & 15) << 4) | (c >> 2));
    if (s[i + 3] !== '=') out.push(((c & 3) << 6) | d);
  }
  return new Uint8Array(out);
}

async function sha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

// Konvertiert rohe 64-Byte ECDSA-Signatur (r||s) in DER-Format
function rawEcdsaToDer(raw) {
  const r = raw.slice(0, 32);
  const s = raw.slice(32, 64);

  function encDerInt(bytes) {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    let val = Array.from(bytes.slice(start));
    if (val[0] & 0x80) val = [0x00, ...val];
    return [0x02, val.length, ...val];
  }

  const rEnc = encDerInt(r);
  const sEnc = encDerInt(s);
  const inner = [...rEnc, ...sEnc];
  return new Uint8Array([0x30, inner.length, ...inner]);
}

// ─── Authenticator Data aufbauen ─────────────────────────────────────────────

async function buildAuthData(rpId, flags, counter, credentialId, publicKeyRaw) {
  const rpIdHash = await sha256(new TextEncoder().encode(rpId));

  const counterBytes = new Uint8Array(4);
  const view = new DataView(counterBytes.buffer);
  view.setUint32(0, counter, false); // big-endian

  if (credentialId && publicKeyRaw) {
    // COSE-Key für P-256
    const x = publicKeyRaw.slice(1, 33);
    const y = publicKeyRaw.slice(33, 65);

    const coseKey = cborEncode(['__map', [
      [1, 2],    // kty: EC2
      [3, -7],   // alg: ES256
      [-1, 1],   // crv: P-256
      [-2, x],   // x
      [-3, y],   // y
    ]]);

    const credIdLen = new Uint8Array(2);
    new DataView(credIdLen.buffer).setUint16(0, credentialId.length, false);

    const aaguid = new Uint8Array(16); // alle Nullen

    const authData = new Uint8Array([
      ...rpIdHash,
      flags,
      ...counterBytes,
      ...aaguid,
      ...credIdLen,
      ...credentialId,
      ...coseKey,
    ]);
    return authData;
  } else {
    return new Uint8Array([...rpIdHash, flags, ...counterBytes]);
  }
}

// ─── Passkey-Registrierung ───────────────────────────────────────────────────

async function handleCreate(options, origin, hostname) {
  const opts = deserializeOptions(options);

  const rpId = (opts.rp && opts.rp.id) ? opts.rp.id : hostname;

  // Sicherheit: rpId muss zur aktuellen Domain gehören
  if (rpId !== hostname && !hostname.endsWith('.' + rpId)) {
    throw new DOMException(
      t('errorInvalidRpId', rpId, hostname),
      'SecurityError'
    );
  }
  const rpName = (opts.rp && opts.rp.name) ? opts.rp.name : rpId;
  const userId = opts.user ? deserializeBuffer(opts.user.id) : randomBytes(16);
  const userName = opts.user ? opts.user.name : '';
  const userDisplayName = opts.user ? opts.user.displayName : '';

  const challenge = deserializeBuffer(opts.challenge);

  // P-256 Schlüsselpaar erzeugen
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const credentialId = randomBytes(16);
  const publicKeyRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', keyPair.publicKey)
  );
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  // clientDataJSON
  const clientData = {
    type: 'webauthn.create',
    challenge: base64urlEncode(Array.from(challenge)),
    origin,
    crossOrigin: false,
  };
  const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));
  const clientDataHash = await sha256(clientDataJSON);

  // AuthenticatorData: flags = UP(0x01) | UV(0x04) | AT(0x40)
  const authData = await buildAuthData(rpId, 0x45, 0, credentialId, publicKeyRaw);

  // AttestationObject (none-Attestierung)
  const attObj = new Uint8Array(cborEncode(['__map', [
    ['fmt', 'none'],
    ['attStmt', ['__map', []]],
    ['authData', authData],
  ]]));

  const credIdStr = base64urlEncode(Array.from(credentialId));
  const x = Array.from(publicKeyRaw.slice(1, 33));
  const y = Array.from(publicKeyRaw.slice(33, 65));

  // Passkey speichern
  await storePasskey({
    credentialId: credIdStr,
    rpId,
    rpName,
    userId: base64urlEncode(Array.from(userId instanceof Uint8Array ? userId : new Uint8Array(userId))),
    userName,
    userDisplayName,
    privateKeyJwk,
    publicKeyX: x,
    publicKeyY: y,
    counter: 0,
    created: new Date().toISOString(),
  });

  return {
    id: credIdStr,
    rawId: Array.from(credentialId),
    response: {
      clientDataJSON: Array.from(clientDataJSON),
      attestationObject: Array.from(attObj),
      authenticatorData: Array.from(authData),
    },
  };
}

// ─── Passkey-Authentifizierung ───────────────────────────────────────────────

async function handleGet(options, origin, hostname) {
  const opts = deserializeOptions(options);

  const rpId = opts.rpId || hostname;
  const challenge = deserializeBuffer(opts.challenge);

  const passkeys = await loadPasskeys();
  // Exakter Treffer zuerst, dann rpId als Domain-Suffix (z.B. "example.com" für "www.example.com")
  console.log('[Passkey] Suche für rpId=' + rpId + ' hostname=' + hostname +
    ' | Gespeichert: ' + passkeys.map(p => p.rpId).join(', ') || '(keine)');

  let candidates = passkeys.filter(pk => pk.rpId === rpId);

  if (candidates.length === 0) {
    candidates = passkeys.filter(pk =>
      hostname.endsWith('.' + pk.rpId) || pk.rpId.endsWith('.' + hostname)
    );
  }

  // Letzter Versuch: auch nach opts.rpId direkt suchen falls hostname abweicht
  if (candidates.length === 0 && opts.rpId && opts.rpId !== hostname) {
    candidates = passkeys.filter(pk =>
      pk.rpId === opts.rpId ||
      opts.rpId.endsWith('.' + pk.rpId) ||
      pk.rpId.endsWith('.' + opts.rpId)
    );
  }

  if (candidates.length === 0) {
    const stored = passkeys.map(p => p.rpId).join(', ') || t('listNone');
    throw new DOMException(
      t('errorNoPasskeyFound', rpId, stored),
      'NotAllowedError'
    );
  }

  // Wenn allowCredentials angegeben, nur diese verwenden
  let passkey = candidates[0];
  if (opts.allowCredentials && opts.allowCredentials.length > 0) {
    const allowed = opts.allowCredentials.map(c => {
      const id = deserializeBuffer(c.id);
      return base64urlEncode(Array.from(id));
    });
    const match = candidates.find(pk => allowed.includes(pk.credentialId));
    if (!match) throw new DOMException(t('errorNoAllowedPasskey'), 'NotAllowedError');
    passkey = match;
  }

  // clientDataJSON
  const clientData = {
    type: 'webauthn.get',
    challenge: base64urlEncode(Array.from(challenge)),
    origin,
    crossOrigin: false,
  };
  const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));
  const clientDataHash = await sha256(clientDataJSON);

  // Counter erhöhen
  passkey.counter = (passkey.counter || 0) + 1;
  await updatePasskey(passkey);

  // AuthenticatorData: flags = UP(0x01) | UV(0x04)
  const authData = await buildAuthData(rpId, 0x05, passkey.counter, null, null);

  // Privaten Schlüssel laden
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    passkey.privateKeyJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  // Signatur: authData || clientDataHash
  const signInput = new Uint8Array([...authData, ...clientDataHash]);
  const rawSig = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, signInput)
  );

  const derSig = rawEcdsaToDer(rawSig);
  const credentialId = base64urlDecode(passkey.credentialId);
  const userId = base64urlDecode(passkey.userId);

  return {
    id: passkey.credentialId,
    rawId: Array.from(credentialId),
    response: {
      clientDataJSON: Array.from(clientDataJSON),
      authenticatorData: Array.from(authData),
      signature: Array.from(derSig),
      userHandle: Array.from(userId),
    },
  };
}

// ─── Speicher ─────────────────────────────────────────────────────────────────
//
// storage.local enthält:
//   passkeys         – die Passkeys, jeweils mit `modified` (letzte Änderung)
//   deletedPasskeys  – gelöschte Credential IDs mit Zeitpunkt, damit der Sync
//                      einen gelöschten Passkey nicht vom anderen PC zurückholt

// Lese-Ändere-Schreibe-Abläufe nacheinander ausführen, damit sich Anmeldung,
// Löschen, Import und Sync nicht gegenseitig überschreiben.
let storageQueue = Promise.resolve();
function withStorageLock(fn) {
  const run = storageQueue.then(fn, fn);
  storageQueue = run.catch(() => {});
  return run;
}

async function loadPasskeys() {
  const result = await browser.storage.local.get('passkeys');
  return result.passkeys || [];
}

async function loadStore() {
  const result = await browser.storage.local.get(['passkeys', 'deletedPasskeys']);
  return { passkeys: result.passkeys || [], deleted: result.deletedPasskeys || [] };
}

async function saveStore(store) {
  await browser.storage.local.set({ passkeys: store.passkeys, deletedPasskeys: store.deleted });
  onPasskeysChanged();
}

function storePasskey(passkey) {
  return withStorageLock(async () => {
    const store = await loadStore();
    store.passkeys.push({ ...passkey, modified: new Date().toISOString() });
    await saveStore(store);
  });
}

function updatePasskey(updated) {
  return withStorageLock(async () => {
    const store = await loadStore();
    const idx = store.passkeys.findIndex(pk => pk.credentialId === updated.credentialId);
    if (idx < 0) return;
    // Der Zähler darf nie zurückgehen, auch wenn ein Sync dazwischen lag
    const counter = Math.max(updated.counter || 0, store.passkeys[idx].counter || 0);
    store.passkeys[idx] = { ...updated, counter, modified: new Date().toISOString() };
    await saveStore(store);
  });
}

function deletePasskey(credentialId) {
  return withStorageLock(async () => {
    const store = await loadStore();
    store.passkeys = store.passkeys.filter(pk => pk.credentialId !== credentialId);
    store.deleted = store.deleted.filter(d => d.credentialId !== credentialId);
    store.deleted.push({ credentialId, deleted: new Date().toISOString() });
    await saveStore(store);
  });
}

// Prüft, ob ein importierter Eintrag alles hat, was handleGet zum Signieren braucht
function isValidPasskey(pk) {
  const isBytes = arr => Array.isArray(arr) && arr.length === 32 &&
    arr.every(b => Number.isInteger(b) && b >= 0 && b <= 255);
  return !!pk && typeof pk === 'object' &&
    typeof pk.credentialId === 'string' && pk.credentialId !== '' &&
    typeof pk.rpId === 'string' && pk.rpId !== '' &&
    typeof pk.userId === 'string' &&
    !!pk.privateKeyJwk && pk.privateKeyJwk.kty === 'EC' && pk.privateKeyJwk.crv === 'P-256' &&
    typeof pk.privateKeyJwk.d === 'string' &&
    isBytes(pk.publicKeyX) && isBytes(pk.publicKeyY) &&
    Number.isInteger(pk.counter) && pk.counter >= 0;
}

function isValidTombstone(d) {
  return !!d && typeof d.credentialId === 'string' && typeof d.deleted === 'string';
}

const modifiedOf = pk => pk.modified || pk.created || '';

// Führt zwei Stände zusammen. Pro Credential ID gewinnt das jüngste Ereignis:
// eine Änderung am Passkey oder sein Löschen. Der Zähler ist immer das Maximum
// beider Seiten, damit Websites den Passkey nicht wegen eines zurückgesetzten
// Zählers ablehnen. Liefert den neuen Stand und was sich lokal geändert hat.
function mergeStores(local, remote) {
  const passkeys = new Map(local.passkeys.map(pk => [pk.credentialId, pk]));
  const deleted = new Map(local.deleted.map(d => [d.credentialId, d.deleted]));
  let added = 0, updated = 0, removed = 0;

  for (const d of remote.deleted.filter(isValidTombstone)) {
    if (!deleted.has(d.credentialId) || d.deleted > deleted.get(d.credentialId)) {
      deleted.set(d.credentialId, d.deleted);
    }
  }

  for (const pk of remote.passkeys.filter(isValidPasskey)) {
    const mine = passkeys.get(pk.credentialId);
    if (!mine) {
      passkeys.set(pk.credentialId, pk);
      added++;
    } else if (pk.counter > mine.counter || modifiedOf(pk) > modifiedOf(mine)) {
      const newer = modifiedOf(pk) > modifiedOf(mine) ? pk : mine;
      const merged = { ...newer, counter: Math.max(pk.counter, mine.counter) };
      if (JSON.stringify(merged) !== JSON.stringify(mine)) updated++;
      passkeys.set(pk.credentialId, merged);
    }
  }

  // Löschen gewinnt nur, wenn es nach der letzten Änderung des Passkeys passierte
  for (const [id, when] of deleted) {
    const pk = passkeys.get(id);
    if (!pk) continue;
    if (when >= modifiedOf(pk)) {
      passkeys.delete(id);
      if (local.passkeys.some(p => p.credentialId === id)) removed++;
      else added--;
    } else {
      deleted.delete(id);
    }
  }

  return {
    store: {
      passkeys: [...passkeys.values()],
      deleted: [...deleted].map(([credentialId, when]) => ({ credentialId, deleted: when })),
    },
    added, updated, removed,
  };
}

// Import aus einer Backup-Datei. Importierte Passkeys gelten als gerade
// geändert, damit sie auch einen früher gelöschten Stand wiederherstellen.
function importPasskeys(imported) {
  if (!Array.isArray(imported)) return Promise.reject(new Error('Invalid backup'));
  return withStorageLock(async () => {
    const now = new Date().toISOString();
    const local = await loadStore();
    const known = new Set(local.passkeys.map(pk => pk.credentialId));
    const valid = imported.filter(isValidPasskey)
      .map(pk => known.has(pk.credentialId) ? pk : { ...pk, modified: now });
    const { store, added, updated } = mergeStores(local, { passkeys: valid, deleted: [] });
    await saveStore(store);
    return { added, updated, skipped: imported.length - added - updated };
  });
}

// ─── Message Handler ──────────────────────────────────────────────────────────

async function hasPasskey(options, hostname) {
  const opts = deserializeOptions(options);
  const rpId = opts.rpId || hostname;
  const passkeys = await loadPasskeys();
  const found =
    passkeys.some(pk => pk.rpId === rpId) ||
    passkeys.some(pk => hostname.endsWith('.' + pk.rpId) || pk.rpId.endsWith('.' + hostname)) ||
    (opts.rpId && passkeys.some(pk =>
      pk.rpId === opts.rpId ||
      opts.rpId.endsWith('.' + pk.rpId) ||
      pk.rpId.endsWith('.' + opts.rpId)
    ));
  return { found: !!found };
}

browser.runtime.onMessage.addListener(function (msg, sender) {
  if (msg.action === 'webauthn-check') {
    return hasPasskey(msg.options, msg.hostname);
  }

  if (msg.action === 'webauthn-create') {
    return handleCreate(msg.options, msg.origin, msg.hostname)
      .then(result => { console.log('[Passkey] create OK', result.id); return { success: true, ...result }; })
      .catch(err => { console.error('[Passkey] create FEHLER', err); return { error: { name: err.name || 'Error', message: err.message } }; });
  }

  if (msg.action === 'webauthn-get') {
    return handleGet(msg.options, msg.origin, msg.hostname)
      .then(result => { console.log('[Passkey] get OK', result.id); return { success: true, ...result }; })
      .catch(err => { console.error('[Passkey] get FEHLER', err.name, err.message); return { error: { name: err.name || 'Error', message: err.message } }; });
  }

  if (msg.action === 'list-passkeys') {
    return loadPasskeys().then(list => ({ passkeys: list }));
  }

  if (msg.action === 'delete-passkey') {
    return deletePasskey(msg.credentialId).then(() => ({ success: true }));
  }

  // Ab hier nur für Seiten des Addons selbst, nie aus einem Content Script
  if (!sender.url || !sender.url.startsWith(browser.runtime.getURL(''))) return;

  if (msg.action === 'import-passkeys') {
    return importPasskeys(msg.passkeys)
      .catch(err => ({ error: err.message }));
  }

  if (msg.action === 'sync-get-settings') {
    return getSyncSettings();
  }

  if (msg.action === 'sync-save-settings') {
    return saveSyncSettings(msg.settings);
  }

  if (msg.action === 'sync-now') {
    return syncNow().then(() => getSyncSettings());
  }

  if (msg.action === 'sync-disable') {
    return disableSync();
  }

  if (msg.action === 'fxsync-get-settings') {
    return getFxSyncSettings();
  }

  if (msg.action === 'fxsync-save-settings') {
    return saveFxSyncSettings(msg.settings);
  }

  if (msg.action === 'fxsync-now') {
    return fxSyncNow().then(() => getFxSyncSettings());
  }

  if (msg.action === 'fxsync-disable') {
    return disableFxSync();
  }
});
