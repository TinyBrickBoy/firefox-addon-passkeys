// Background-Script: Krypto-Operationen und Passkey-Speicherung

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
      `rpId "${rpId}" ist nicht gültig für Origin "${hostname}"`,
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
    const stored = passkeys.map(p => p.rpId).join(', ') || '(keine)';
    throw new DOMException(
      `Kein Passkey für "${rpId}" – gespeichert: [${stored}]. Bitte erst Passkey erstellen.`,
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
    if (!match) throw new DOMException('Keiner der erlaubten Passkeys gefunden', 'NotAllowedError');
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

async function loadPasskeys() {
  const result = await browser.storage.local.get('passkeys');
  return result.passkeys || [];
}

async function storePasskey(passkey) {
  const passkeys = await loadPasskeys();
  passkeys.push(passkey);
  await browser.storage.local.set({ passkeys });
}

async function updatePasskey(updated) {
  const passkeys = await loadPasskeys();
  const idx = passkeys.findIndex(pk => pk.credentialId === updated.credentialId);
  if (idx >= 0) passkeys[idx] = updated;
  await browser.storage.local.set({ passkeys });
}

async function deletePasskey(credentialId) {
  const passkeys = await loadPasskeys();
  const filtered = passkeys.filter(pk => pk.credentialId !== credentialId);
  await browser.storage.local.set({ passkeys: filtered });
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

  if (msg.action === 'nextcloud-get-config') {
    return browser.storage.local.get('nextcloud').then(r => ({ config: r.nextcloud || null }));
  }

  if (msg.action === 'nextcloud-set-config') {
    return browser.storage.local.set({ nextcloud: msg.config }).then(() => ({ success: true }));
  }

  if (msg.action === 'nextcloud-export') {
    return nextcloudExport()
      .then(info => ({ success: true, ...info }))
      .catch(err => ({ error: { name: err.name || 'Error', message: err.message } }));
  }

  if (msg.action === 'nextcloud-import') {
    return nextcloudImport(msg.mode || 'merge')
      .then(info => ({ success: true, ...info }))
      .catch(err => ({ error: { name: err.name || 'Error', message: err.message } }));
  }
});

// ─── Nextcloud Sync (WebDAV) ─────────────────────────────────────────────────

function buildWebdavUrl(cfg) {
  const base = cfg.url.replace(/\/+$/, '');
  const user = encodeURIComponent(cfg.username);
  const path = (cfg.path || 'passkeys.json').replace(/^\/+/, '');
  return `${base}/remote.php/dav/files/${user}/${path}`;
}

function basicAuthHeader(cfg) {
  const raw = `${cfg.username}:${cfg.password}`;
  // btoa erwartet Latin-1; UTF-8 sicher kodieren
  const bytes = new TextEncoder().encode(raw);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return 'Basic ' + btoa(bin);
}

async function loadNextcloudConfig() {
  const r = await browser.storage.local.get('nextcloud');
  if (!r.nextcloud || !r.nextcloud.url || !r.nextcloud.username || !r.nextcloud.password) {
    throw new Error('Nextcloud-Zugang ist nicht vollständig konfiguriert.');
  }
  return r.nextcloud;
}

async function deriveKey(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptPayload(plaintextStr, passphrase) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKey(passphrase, salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintextStr)
  ));
  return JSON.stringify({
    v: 1,
    enc: 'AES-GCM-PBKDF2',
    iter: 200000,
    salt: base64urlEncode(Array.from(salt)),
    iv: base64urlEncode(Array.from(iv)),
    ct: base64urlEncode(Array.from(ct)),
  });
}

async function decryptPayload(envelopeStr, passphrase) {
  const env = JSON.parse(envelopeStr);
  if (env && env.enc === 'AES-GCM-PBKDF2') {
    const salt = base64urlDecode(env.salt);
    const iv = base64urlDecode(env.iv);
    const ct = base64urlDecode(env.ct);
    const key = await deriveKey(passphrase, salt);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(pt);
  }
  // Unverschlüsselt erlaubt
  return envelopeStr;
}

async function nextcloudExport() {
  const cfg = await loadNextcloudConfig();
  const passkeys = await loadPasskeys();
  const payload = {
    type: 'linux-passkey-manager-backup',
    version: 1,
    exported: new Date().toISOString(),
    passkeys,
  };
  let body = JSON.stringify(payload);
  let contentType = 'application/json';
  if (cfg.passphrase) {
    body = await encryptPayload(body, cfg.passphrase);
    contentType = 'application/json';
  }
  const url = buildWebdavUrl(cfg);
  const res = await fetch(url, {
    method: 'PUT',
    headers: { 'Authorization': basicAuthHeader(cfg), 'Content-Type': contentType },
    body,
  });
  if (!res.ok) {
    throw new Error(`Upload fehlgeschlagen (${res.status} ${res.statusText})`);
  }
  return { count: passkeys.length, encrypted: !!cfg.passphrase };
}

async function nextcloudImport(mode) {
  const cfg = await loadNextcloudConfig();
  const url = buildWebdavUrl(cfg);
  const res = await fetch(url, {
    method: 'GET',
    headers: { 'Authorization': basicAuthHeader(cfg) },
  });
  if (res.status === 404) throw new Error('Datei auf Nextcloud nicht gefunden.');
  if (!res.ok) throw new Error(`Download fehlgeschlagen (${res.status} ${res.statusText})`);
  const text = await res.text();

  let plaintext;
  try {
    plaintext = await decryptPayload(text, cfg.passphrase || '');
  } catch (e) {
    throw new Error('Entschlüsselung fehlgeschlagen – Passphrase prüfen.');
  }

  let payload;
  try {
    payload = JSON.parse(plaintext);
  } catch (e) {
    throw new Error('Ungültiges Backup-Format.');
  }
  const incoming = Array.isArray(payload) ? payload : payload.passkeys;
  if (!Array.isArray(incoming)) throw new Error('Backup enthält keine Passkeys.');

  let existing = await loadPasskeys();
  let added = 0;
  if (mode === 'replace') {
    existing = incoming;
    added = incoming.length;
  } else {
    const known = new Set(existing.map(p => p.credentialId));
    for (const pk of incoming) {
      if (!known.has(pk.credentialId)) {
        existing.push(pk);
        known.add(pk.credentialId);
        added++;
      }
    }
  }
  await browser.storage.local.set({ passkeys: existing });
  return { total: incoming.length, added, mode };
}
