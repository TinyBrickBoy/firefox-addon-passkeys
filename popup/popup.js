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
    const body = document.createElement('div');
    body.className = 'item-body';

    const siteEl = document.createElement('div');
    siteEl.className = 'item-site';
    siteEl.title = pk.rpId;
    siteEl.textContent = name;
    body.appendChild(siteEl);

    const userEl = document.createElement('div');
    userEl.className = 'item-user';
    userEl.textContent = user;
    body.appendChild(userEl);

    if (meta) {
      const metaEl = document.createElement('div');
      metaEl.className = 'item-meta';
      metaEl.textContent = meta;
      body.appendChild(metaEl);
    }

    const delBtn = document.createElement('button');
    delBtn.className = 'btn-del';
    delBtn.title = 'Löschen';
    delBtn.textContent = '✕';

    li.appendChild(body);
    li.appendChild(delBtn);

    delBtn.onclick = () => {
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
