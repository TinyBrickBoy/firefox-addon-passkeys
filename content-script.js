// Content-Script: Injiziert injected.js und zeigt Passkey-UI
(function () {
  const script = document.createElement('script');
  script.src = browser.runtime.getURL('injected.js');
  script.onload = function () { script.remove(); };
  (document.head || document.documentElement).appendChild(script);

  let activeModal = null;

  // Verhindert XSS durch Website-kontrollierte Werte in innerHTML
  function esc(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  window.addEventListener('message', async function (event) {
    if (event.source !== window) return;
    const msg = event.data;
    if (!msg || msg._passkeyAddon !== 'request') return;

    const { type, id, options } = msg;

    try {
      // Bei "get": erst prüfen ob überhaupt ein Passkey gespeichert ist
      if (type === 'get') {
        const check = await browser.runtime.sendMessage({
          action: 'webauthn-check',
          options,
          hostname: window.location.hostname,
        });
        if (!check.found) {
          // Kein Passkey → Browser-Standardverhalten fortsetzen, kein Popup
          respond(id, null, { name: 'passthrough' });
          return;
        }
      }

      const confirmed = await showModal(type, options);
      if (!confirmed) {
        respond(id, null, { name: 'NotAllowedError', message: 'Abgebrochen' });
        return;
      }

      let result;
      try {
        result = await browser.runtime.sendMessage({
          action: type === 'create' ? 'webauthn-create' : 'webauthn-get',
          options,
          origin: window.location.origin,
          hostname: window.location.hostname,
        });
      } catch (err) {
        showError(err.message || String(err));
        respond(id, null, { name: 'UnknownError', message: err.message });
        return;
      }

      if (result.error) {
        showError(result.error.message || 'Unbekannter Fehler');
        respond(id, null, result.error);
      } else {
        respond(id, { ...result, type }, null);
      }
    } catch (err) {
      respond(id, null, { name: 'UnknownError', message: err.message });
    }
  });

  function respond(id, result, error) {
    window.postMessage({ _passkeyAddon: 'response', id, result, error }, '*');
  }

  // ─── Modal-Grundgerüst ─────────────────────────────────────────────────────

  function createShadowModal(html) {
    if (activeModal) { activeModal.remove(); activeModal = null; }
    const host = document.createElement('div');
    host.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647;';
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = html;
    document.documentElement.appendChild(host);
    activeModal = host;
    return shadow;
  }

  function closeModal() {
    if (activeModal) { activeModal.remove(); activeModal = null; }
  }

  // ─── Bestätigungs-Modal ────────────────────────────────────────────────────

  const MODAL_STYLE = `
    <style>
      *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
      :host { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; }

      /* Light */
      :host {
        --bg:      #ffffff;
        --bg-icon: #f0f0f5;
        --border:  rgba(0,0,0,0.06);
        --text:    #111111;
        --muted:   #666666;
        --btn-sec-bg:   #f0f0f5;
        --btn-sec-fg:   #555555;
        --btn-pri-bg:   #111111;
        --btn-pri-fg:   #ffffff;
        --shadow:  0 20px 60px rgba(0,0,0,0.18), 0 0 0 1px rgba(0,0,0,0.06);
        --overlay: rgba(0,0,0,0.4);
      }
      /* Dark */
      @media (prefers-color-scheme: dark) {
        :host {
          --bg:      #1c1c1e;
          --bg-icon: #2c2c2e;
          --border:  rgba(255,255,255,0.08);
          --text:    #f2f2f7;
          --muted:   #98989f;
          --btn-sec-bg:   #2c2c2e;
          --btn-sec-fg:   #ebebf5;
          --btn-pri-bg:   #f2f2f7;
          --btn-pri-fg:   #111111;
          --shadow:  0 20px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.06);
          --overlay: rgba(0,0,0,0.6);
        }
      }

      .backdrop {
        position: fixed; inset: 0;
        background: var(--overlay);
        backdrop-filter: blur(4px);
        display: flex; align-items: center; justify-content: center;
        padding: 20px;
        animation: fadeIn 0.15s ease;
      }
      @keyframes fadeIn { from { opacity: 0 } to { opacity: 1 } }
      .card {
        background: var(--bg);
        border-radius: 20px;
        padding: 32px 28px 24px;
        width: 100%; max-width: 360px;
        box-shadow: var(--shadow);
        animation: slideUp 0.18s cubic-bezier(0.34, 1.56, 0.64, 1);
      }
      @keyframes slideUp { from { opacity:0; transform:translateY(12px) } to { opacity:1; transform:translateY(0) } }
      .title { font-size: 17px; font-weight: 700; color: var(--text); margin-bottom: 6px; }
      .desc { font-size: 14px; color: var(--muted); line-height: 1.5; margin-bottom: 24px; }
      .desc strong { color: var(--text); font-weight: 600; }
      .desc em { color: var(--muted); font-style: normal; }
      .actions { display: flex; gap: 8px; justify-content: flex-end; }
      .btn {
        height: 38px; padding: 0 18px; border: none; border-radius: 10px;
        font-size: 14px; font-weight: 600; cursor: pointer;
        transition: opacity 0.12s, transform 0.1s;
      }
      .btn:hover { opacity: 0.8; }
      .btn:active { transform: scale(0.97); }
      .btn-cancel  { background: var(--btn-sec-bg); color: var(--btn-sec-fg); }
      .btn-confirm { background: var(--btn-pri-bg); color: var(--btn-pri-fg); }
    </style>
  `;

  function showModal(type, options) {
    return new Promise(function (resolve) {
      const isCreate = type === 'create';
      const rpName = esc(options.rp
        ? (options.rp.name || options.rp.id || '')
        : (options.rpId || ''));
      const userName = esc(options.user
        ? (options.user.displayName || options.user.name || '')
        : '');

      const title = isCreate ? 'Passkey erstellen' : 'Mit Passkey anmelden';
      const detail = isCreate
        ? `<strong>${rpName}</strong> möchte einen Passkey erstellen` + (userName ? ` für <em>${userName}</em>` : '') + '.'
        : `<strong>${rpName}</strong> möchte deinen Passkey verwenden.`;
      const btnLabel = isCreate ? 'Erstellen' : 'Anmelden';

      const shadow = createShadowModal(`
        ${MODAL_STYLE}
        <div class="backdrop" id="backdrop">
          <div class="card">
            <div class="title">${title}</div>
            <div class="desc">${detail}</div>
            <div class="actions">
              <button class="btn btn-cancel" id="cancel">Abbrechen</button>
              <button class="btn btn-confirm" id="confirm">${btnLabel}</button>
            </div>
          </div>
        </div>
      `);

      shadow.getElementById('confirm').onclick = () => { closeModal(); resolve(true); };
      shadow.getElementById('cancel').onclick = () => { closeModal(); resolve(false); };
      shadow.getElementById('backdrop').onclick = (e) => {
        if (e.target === shadow.getElementById('backdrop')) { closeModal(); resolve(false); }
      };
    });
  }

  // ─── Fehler-Modal ──────────────────────────────────────────────────────────

  function showError(message) {
    const shadow = createShadowModal(`
      ${MODAL_STYLE}
      <div class="backdrop" id="backdrop">
        <div class="card">
          <div class="title" style="color:#c00">Fehler</div>
          <div class="desc" style="word-break:break-word">${esc(message)}</div>
          <div class="actions">
            <button class="btn btn-confirm" id="ok">OK</button>
          </div>
        </div>
      </div>
    `);
    shadow.getElementById('ok').onclick = closeModal;
    shadow.getElementById('backdrop').onclick = (e) => {
      if (e.target === shadow.getElementById('backdrop')) closeModal();
    };
  }
})();
