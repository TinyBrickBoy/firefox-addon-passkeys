// Läuft im Seiten-Kontext (page context) – überschreibt navigator.credentials
(function () {
  if (window.__passkeyAddonInjected) return;
  window.__passkeyAddonInjected = true;

  const originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const originalGet = navigator.credentials.get.bind(navigator.credentials);

  const pending = new Map();

  function bufToArray(val) {
    if (!val) return null;
    if (val instanceof ArrayBuffer) return Array.from(new Uint8Array(val));
    if (ArrayBuffer.isView(val)) return Array.from(new Uint8Array(val.buffer, val.byteOffset, val.byteLength));
    return val;
  }

  function serializeOptions(opts) {
    return JSON.parse(JSON.stringify(opts, function (key, value) {
      if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
        return { __buf: true, data: bufToArray(value) };
      }
      return value;
    }));
  }

  // Empfange Antworten vom Content-Script
  window.addEventListener('message', function (event) {
    if (event.source !== window) return;
    const msg = event.data;
    if (!msg || msg._passkeyAddon !== 'response') return;

    const entry = pending.get(msg.id);
    if (!entry) return;
    pending.delete(msg.id);

    if (msg.error && msg.error.name === 'passthrough') {
      // Kein Passkey gespeichert → original Browser-Flow
      const origOptions = entry.options;
      originalGet(origOptions).then(entry.resolve).catch(entry.reject);
    } else if (msg.error) {
      entry.reject(new DOMException(msg.error.message || 'Passkey-Fehler', msg.error.name || 'NotAllowedError'));
    } else {
      entry.resolve(deserializeCredential(msg.result));
    }
  });

  function toBuffer(arr) {
    return new Uint8Array(arr).buffer;
  }

  function makeProp(value) {
    return { value, writable: true, enumerable: true, configurable: true };
  }

  function deserializeCredential(raw) {
    if (!raw) return null;

    const clientDataJSON = toBuffer(raw.response.clientDataJSON);
    const id = raw.id;
    const rawIdBuf = toBuffer(raw.rawId);

    let response;
    if (raw.type === 'create') {
      const attestationObject = toBuffer(raw.response.attestationObject);
      const authenticatorData = toBuffer(raw.response.authenticatorData);

      try {
        response = Object.create(AuthenticatorAttestationResponse.prototype);
        Object.defineProperties(response, {
          clientDataJSON: makeProp(clientDataJSON),
          attestationObject: makeProp(attestationObject),
          getAuthenticatorData: makeProp(() => authenticatorData),
          getPublicKey: makeProp(() => null),
          getPublicKeyAlgorithm: makeProp(() => -7),
          getTransports: makeProp(() => ['internal']),
        });
      } catch (_) {
        response = {
          clientDataJSON, attestationObject,
          getAuthenticatorData: () => authenticatorData,
          getPublicKey: () => null, getPublicKeyAlgorithm: () => -7,
          getTransports: () => ['internal'],
        };
      }
    } else {
      const authenticatorData = toBuffer(raw.response.authenticatorData);
      const signature = toBuffer(raw.response.signature);
      const uh = raw.response.userHandle;
      const userHandle = uh && uh.length > 0 ? toBuffer(uh) : null;

      try {
        response = Object.create(AuthenticatorAssertionResponse.prototype);
        Object.defineProperties(response, {
          clientDataJSON: makeProp(clientDataJSON),
          authenticatorData: makeProp(authenticatorData),
          signature: makeProp(signature),
          userHandle: makeProp(userHandle),
          getAuthenticatorData: makeProp(() => authenticatorData),
        });
      } catch (_) {
        response = {
          clientDataJSON, authenticatorData, signature, userHandle,
          getAuthenticatorData: () => authenticatorData,
        };
      }
    }

    let credential;
    try {
      credential = Object.create(PublicKeyCredential.prototype);
      Object.defineProperties(credential, {
        id: makeProp(id),
        rawId: makeProp(rawIdBuf),
        type: makeProp('public-key'),
        response: makeProp(response),
        authenticatorAttachment: makeProp('platform'),
        getClientExtensionResults: makeProp(() => ({})),
      });
    } catch (_) {
      credential = {
        id, rawId: rawIdBuf, type: 'public-key', response,
        authenticatorAttachment: 'platform',
        getClientExtensionResults: () => ({}),
      };
    }

    return credential;
  }

  navigator.credentials.create = function (options) {
    if (!options || !options.publicKey) return originalCreate(options);

    return new Promise(function (resolve, reject) {
      const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
      pending.set(id, { resolve, reject });

      window.postMessage({
        _passkeyAddon: 'request',
        type: 'create',
        id,
        options: serializeOptions(options.publicKey),
      }, '*');

      // Timeout nach 5 Minuten
      setTimeout(function () {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new DOMException('Zeitüberschreitung', 'TimeoutError'));
        }
      }, 300000);
    });
  };

  navigator.credentials.get = function (options) {
    if (!options || !options.publicKey) return originalGet(options);

    return new Promise(function (resolve, reject) {
      const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
      pending.set(id, { resolve, reject, options });

      window.postMessage({
        _passkeyAddon: 'request',
        type: 'get',
        id,
        options: serializeOptions(options.publicKey),
      }, '*');

      setTimeout(function () {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new DOMException('Zeitüberschreitung', 'TimeoutError'));
        }
      }, 300000);
    });
  };
})();
