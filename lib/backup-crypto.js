// Verschlüsseltes Dateiformat für Backups und den Nextcloud-Sync.
// Wird vom Background-Script und von der Backup-Seite geladen.
//
// Die Passkeys enthalten private Schlüssel, darum wird alles mit einem Passwort
// verschlüsselt: PBKDF2-SHA-256 leitet den Schlüssel ab, AES-GCM verschlüsselt
// und erkennt dabei auch ein falsches Passwort.
//
// Fehler tragen einen `code`: 'invalid' (keine gültige Datei) oder
// 'wrong-password' (Entschlüsseln fehlgeschlagen).

const BackupCrypto = (function () {
  const FORMAT = 'linux-passkey-manager-backup';
  const VERSION = 1;
  const ITERATIONS = 600000;

  // Das Ableiten dauert absichtlich lange. Der Sync verschlüsselt mit demselben
  // Passwort und Salt mehrmals, darum wird der letzte Schlüssel gemerkt.
  let cachedKey = null;

  function toBase64(bytes) {
    let bin = '';
    bytes.forEach(b => { bin += String.fromCharCode(b); });
    return btoa(bin);
  }

  function fromBase64(str) {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
  }

  function fail(code) {
    const err = new Error(code);
    err.code = code;
    return err;
  }

  async function deriveKey(password, salt, iterations) {
    const id = [password, toBase64(salt), iterations].join('\u0000');
    if (cachedKey && cachedKey.id === id) return cachedKey.key;

    const material = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    cachedKey = { id, key };
    return key;
  }

  // payload: { passkeys: [...], deleted: [...] }
  // salt: optional, um beim Sync den Salt der vorhandenen Datei weiterzuverwenden
  async function encrypt(payload, password, salt) {
    salt = salt || crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt, ITERATIONS);
    const plain = new TextEncoder().encode(JSON.stringify(payload));
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
    return {
      format: FORMAT,
      version: VERSION,
      created: new Date().toISOString(),
      count: payload.passkeys.length,
      kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS, salt: toBase64(salt) },
      cipher: { name: 'AES-GCM', iv: toBase64(iv) },
      data: toBase64(new Uint8Array(cipher)),
    };
  }

  // Liefert { payload, salt }
  async function decrypt(file, password) {
    if (!file || file.format !== FORMAT || file.version !== VERSION ||
        !file.kdf || !file.cipher || typeof file.data !== 'string' ||
        !Number.isInteger(file.kdf.iterations) || file.kdf.iterations < 1) {
      throw fail('invalid');
    }

    let salt, iv, data;
    try {
      salt = fromBase64(file.kdf.salt);
      iv = fromBase64(file.cipher.iv);
      data = fromBase64(file.data);
    } catch (err) {
      throw fail('invalid');
    }

    const key = await deriveKey(password, salt, file.kdf.iterations);
    let plain;
    try {
      plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    } catch (err) {
      throw fail('wrong-password');
    }

    let payload;
    try {
      payload = JSON.parse(new TextDecoder().decode(plain));
    } catch (err) {
      throw fail('invalid');
    }
    if (!payload || !Array.isArray(payload.passkeys)) throw fail('invalid');
    if (!Array.isArray(payload.deleted)) payload.deleted = [];
    return { payload, salt };
  }

  return { encrypt, decrypt };
})();
