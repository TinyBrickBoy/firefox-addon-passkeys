const $ = id => document.getElementById(id);

const loadingEl = $('loading');
const emptyEl   = $('empty');
const listEl    = $('list');
const dialogEl  = $('dialog');
const dialogMsg = $('dialog-msg');

let pendingId = null;

function fmt(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

function render(passkeys) {
  loadingEl.classList.add('hidden');

  if (!passkeys?.length) {
    emptyEl.classList.remove('hidden');
    return;
  }

  listEl.classList.remove('hidden');
  listEl.innerHTML = '';

  passkeys.forEach(pk => {
    const user = pk.userDisplayName || pk.userName || '–';
    const name = pk.rpName || pk.rpId;
    const meta = [fmt(pk.created), pk.counter ? `${pk.counter}× genutzt` : ''].filter(Boolean).join(' · ');

    const li = document.createElement('li');
    li.className = 'item';
    li.innerHTML = `
      <div class="item-body">
        <div class="item-site" title="${pk.rpId}">${name}</div>
        <div class="item-user">${user}</div>
        ${meta ? `<div class="item-meta">${meta}</div>` : ''}
      </div>
      <button class="btn-del" title="Löschen" data-id="${pk.credentialId}">✕</button>
    `;

    li.querySelector('.btn-del').onclick = () => {
      pendingId = pk.credentialId;
      dialogMsg.textContent = `Passkey für „${name}" (${user}) wird unwiderruflich gelöscht.`;
      dialogEl.classList.remove('hidden');
    };

    listEl.appendChild(li);
  });
}

$('btn-cancel').onclick = () => { pendingId = null; dialogEl.classList.add('hidden'); };

$('btn-confirm').onclick = async () => {
  if (!pendingId) return;
  const id = pendingId;
  pendingId = null;
  dialogEl.classList.add('hidden');
  await browser.runtime.sendMessage({ action: 'delete-passkey', credentialId: id });
  load();
};

async function load() {
  loadingEl.classList.remove('hidden');
  listEl.classList.add('hidden');
  emptyEl.classList.add('hidden');
  const { passkeys } = await browser.runtime.sendMessage({ action: 'list-passkeys' });
  render(passkeys);
}

load();
