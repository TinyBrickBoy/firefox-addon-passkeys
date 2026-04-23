// Content-Script: Injiziert injected.js und zeigt Passkey-UI
(function () {
  const script = document.createElement('script');
  script.src = browser.runtime.getURL('injected.js');
  script.onload = function () { script.remove(); };
  (document.head || document.documentElement).appendChild(script);

  let activeModal = null;

  window.addEventListener('message', async function (event) {
    if (event.source !== window) return;
    const msg = event.data;
    if (!msg || msg._passkeyAddon !== 'request') return;

    const { type, id, options } = msg;

    try {
      if (type === 'get') {
        const check = await browser.runtime.sendMessage({
          action: 'webauthn-check',
          options,
          hostname: window.location.hostname,
        });
        if (!check.found) {
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

  // ─── Shadow-Host ────────────────────────────────────────────────────────────

  const MODAL_CSS = `
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :host { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; }
    :host {
      --bg:          #ffffff;
      --text:        #111111;
      --muted:       #666666;
      --btn-sec-bg:  #f0f0f5;
      --btn-sec-fg:  #555555;
      --btn-pri-bg:  #111111;
      --btn-pri-fg:  #ffffff;
      --shadow:      0 20px 60px rgba(0,0,0,0.18), 0 0 0 1px rgba(0,0,0,0.06);
      --overlay:     rgba(0,0,0,0.4);
    }
    @media (prefers-color-scheme: dark) {
      :host {
        --bg:          #1c1c1e;
        --text:        #f2f2f7;
        --muted:       #98989f;
        --btn-sec-bg:  #2c2c2e;
        --btn-sec-fg:  #ebebf5;
        --btn-pri-bg:  #f2f2f7;
        --btn-pri-fg:  #111111;
        --shadow:      0 20px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.06);
        --overlay:     rgba(0,0,0,0.6);
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
    @keyframes fadeIn { from { opacity:0 } to { opacity:1 } }
    .card {
      background: var(--bg);
      border-radius: 20px;
      padding: 32px 28px 24px;
      width: 100%; max-width: 360px;
      box-shadow: var(--shadow);
      animation: slideUp 0.18s cubic-bezier(0.34,1.56,0.64,1);
    }
    @keyframes slideUp { from { opacity:0; transform:translateY(12px) } to { opacity:1; transform:translateY(0) } }
    .title  { font-size: 17px; font-weight: 700; color: var(--text); margin-bottom: 6px; }
    .error  { color: #c00; }
    .desc   { font-size: 14px; color: var(--muted); line-height: 1.5; margin-bottom: 24px; word-break: break-word; }
    .desc strong { color: var(--text); font-weight: 600; }
    .actions { display: flex; gap: 8px; justify-content: flex-end; }
    .btn {
      height: 38px; padding: 0 18px; border: none; border-radius: 10px;
      font-size: 14px; font-weight: 600; cursor: pointer;
      transition: opacity 0.12s, transform 0.1s;
    }
    .btn:hover  { opacity: 0.8; }
    .btn:active { transform: scale(0.97); }
    .btn-cancel  { background: var(--btn-sec-bg); color: var(--btn-sec-fg); }
    .btn-confirm { background: var(--btn-pri-bg); color: var(--btn-pri-fg); }
  `;

  function createHost() {
    if (activeModal) { activeModal.remove(); activeModal = null; }
    const host = document.createElement('div');
    host.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647;';
    const shadow = host.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = MODAL_CSS;
    shadow.appendChild(style);
    document.documentElement.appendChild(host);
    activeModal = host;
    return shadow;
  }

  function closeModal() {
    if (activeModal) { activeModal.remove(); activeModal = null; }
  }

  function el(tag, className) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    return node;
  }

  function buildCard(shadow) {
    const backdrop = el('div', 'backdrop');
    const card = el('div', 'card');
    backdrop.appendChild(card);
    shadow.appendChild(backdrop);
    return { backdrop, card };
  }

  // ─── Bestätigungs-Modal ────────────────────────────────────────────────────

  function showModal(type, options) {
    return new Promise(function (resolve) {
      const isCreate = type === 'create';
      const rpName = String(options.rp
        ? (options.rp.name || options.rp.id || '')
        : (options.rpId || ''));
      const userName = String(options.user
        ? (options.user.displayName || options.user.name || '')
        : '');

      const shadow = createHost();
      const { backdrop, card } = buildCard(shadow);

      // Title
      const title = el('div', 'title');
      title.textContent = isCreate ? 'Passkey erstellen' : 'Mit Passkey anmelden';
      card.appendChild(title);

      // Beschreibung mit <strong> und optional <em>
      const desc = el('div', 'desc');
      const strong = el('strong');
      strong.textContent = rpName;
      desc.appendChild(strong);
      if (isCreate) {
        desc.appendChild(document.createTextNode(' möchte einen Passkey erstellen'));
        if (userName) {
          desc.appendChild(document.createTextNode(' für '));
          const em = el('em');
          em.textContent = userName;
          desc.appendChild(em);
        }
        desc.appendChild(document.createTextNode('.'));
      } else {
        desc.appendChild(document.createTextNode(' möchte deinen Passkey verwenden.'));
      }
      card.appendChild(desc);

      // Buttons
      const actions = el('div', 'actions');
      const btnCancel = el('button', 'btn btn-cancel');
      btnCancel.textContent = 'Abbrechen';
      const btnConfirm = el('button', 'btn btn-confirm');
      btnConfirm.textContent = isCreate ? 'Erstellen' : 'Anmelden';
      actions.appendChild(btnCancel);
      actions.appendChild(btnConfirm);
      card.appendChild(actions);

      btnConfirm.onclick = () => { closeModal(); resolve(true); };
      btnCancel.onclick  = () => { closeModal(); resolve(false); };
      backdrop.onclick   = (e) => { if (e.target === backdrop) { closeModal(); resolve(false); } };
    });
  }

  // ─── Fehler-Modal ──────────────────────────────────────────────────────────

  function showError(message) {
    const shadow = createHost();
    const { backdrop, card } = buildCard(shadow);

    const title = el('div', 'title error');
    title.textContent = 'Fehler';
    card.appendChild(title);

    const desc = el('div', 'desc');
    desc.textContent = String(message);
    card.appendChild(desc);

    const actions = el('div', 'actions');
    const btnOk = el('button', 'btn btn-confirm');
    btnOk.textContent = 'OK';
    actions.appendChild(btnOk);
    card.appendChild(actions);

    btnOk.onclick   = closeModal;
    backdrop.onclick = (e) => { if (e.target === backdrop) closeModal(); };
  }
})();
