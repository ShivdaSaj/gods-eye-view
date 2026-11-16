// Admin editor for POWER UP keys and app settings. Builds every node with DOM
// APIs; nothing from the server is ever parsed as HTML.
const keyList = document.getElementById('key-list');
const settingList = document.getElementById('setting-list');
const keyForm = document.getElementById('keys');
const settingForm = document.getElementById('settings');
const filter = document.getElementById('filter');
const notice = document.getElementById('notice');

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === true) node.setAttribute(name, '');
    else if (value !== false && value != null) node.setAttribute(name, value);
  }
  for (const child of children) {
    if (child != null)
      node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

function say(text, kind = 'info') {
  notice.hidden = !text;
  notice.textContent = text || '';
  notice.className = `notice ${kind}`;
}

// ----- tabs -----------------------------------------------------------------

for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => {
    for (const other of document.querySelectorAll('.tab'))
      other.classList.toggle('active', other === tab);
    for (const pane of document.querySelectorAll('.pane'))
      pane.hidden = pane.dataset.pane !== tab.dataset.tab;
    say('');
  });
}

// ----- keys -----------------------------------------------------------------

function renderKeys(keys) {
  keyList.replaceChildren(
    ...keys.map((entry) =>
      el(
        'section',
        { class: 'entry' },
        el(
          'div',
          { class: 'entry-head' },
          el('h2', {}, entry.title),
          el('span', { class: `tier ${entry.tier}` }, entry.tier),
        ),
        el(
          'p',
          { class: 'muted' },
          entry.unlocks,
          ' · ',
          el('a', { href: entry.getUrl, target: '_blank', rel: 'noopener noreferrer' }, 'Get a key'),
        ),
        entry.clientExposed
          ? el('p', { class: 'hint' }, 'Sent to every visitor’s browser by design: restrict it to this domain at the provider.')
          : null,
        ...entry.vars.map((variable) =>
          el(
            'div',
            { class: 'var' },
            el(
              'label',
              { for: `key-${variable.name}` },
              el('code', {}, variable.name),
              el('span', { class: `badge ${variable.set ? 'on' : 'off'}` }, variable.set ? 'Set' : 'Not set'),
            ),
            el('input', {
              id: `key-${variable.name}`,
              'data-name': variable.name,
              type: 'password',
              spellcheck: 'false',
              autocomplete: 'off',
              placeholder: variable.set ? 'Paste a new value to replace it' : 'Paste the key',
            }),
            variable.set
              ? el('label', { class: 'remove' }, el('input', { type: 'checkbox', 'data-remove': variable.name }), ' Remove')
              : null,
          ),
        ),
      ),
    ),
  );
}

// ----- settings -------------------------------------------------------------

function renderSettings(groups) {
  const open = new Set(
    [...settingList.querySelectorAll('details[open]')].map((node) => node.dataset.group),
  );
  settingList.replaceChildren(
    ...groups.map((group) =>
      el(
        'details',
        { class: 'entry group', 'data-group': group.group, open: open.has(group.group) },
        el(
          'summary',
          {},
          el('h2', {}, group.group),
          el('span', { class: 'tier' }, `${group.vars.filter((v) => v.set).length}/${group.vars.length} set`),
        ),
        ...group.vars.map((variable) => {
          const input = el('input', {
            id: `set-${variable.name}`,
            'data-setting': variable.name,
            type: variable.secret ? 'password' : 'text',
            spellcheck: 'false',
            autocomplete: 'off',
            disabled: variable.locked,
            placeholder: variable.secret
              ? variable.set ? 'Set — paste a new value to replace it' : 'Not set'
              : variable.default ? `Default: ${variable.default}` : 'Default (empty)',
          });
          if (!variable.secret) input.value = variable.value;
          input.dataset.original = variable.secret ? '' : variable.value;
          return el(
            'div',
            { class: 'var', 'data-search': `${variable.name} ${variable.description} ${group.group}`.toLowerCase() },
            el(
              'label',
              { for: `set-${variable.name}` },
              el('code', {}, variable.name),
              variable.locked ? el('span', { class: 'badge off' }, 'deployment') : null,
              !variable.locked && variable.set ? el('span', { class: 'badge on' }, 'Custom') : null,
            ),
            variable.description ? el('p', { class: 'help' }, variable.description) : null,
            input,
            !variable.locked && variable.set
              ? el('label', { class: 'remove' }, el('input', { type: 'checkbox', 'data-reset': variable.name }), ' Reset to default')
              : null,
          );
        }),
      ),
    ),
  );
  applyFilter();
}

function applyFilter() {
  const query = filter.value.trim().toLowerCase();
  for (const group of settingList.querySelectorAll('details')) {
    let shown = 0;
    for (const row of group.querySelectorAll('.var')) {
      const match = !query || row.dataset.search.includes(query);
      row.hidden = !match;
      if (match) shown += 1;
    }
    group.hidden = shown === 0;
    if (query && shown) group.open = true;
  }
}
filter.addEventListener('input', applyFilter);

// ----- data -----------------------------------------------------------------

async function api(path, options = {}) {
  const response = await fetch(path, { credentials: 'same-origin', ...options });
  if (response.status === 401) {
    window.location.href = '/admin';
    throw new Error('Signed out');
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

function render(payload) {
  renderKeys(payload.keys);
  renderSettings(payload.settings);
}

async function load() {
  try {
    render(await api('/admin/api/status'));
  } catch (error) {
    say(`Could not load: ${error.message}`, 'error');
  }
}

async function submit(form, path, updates) {
  if (!Object.keys(updates).length) {
    say('Nothing changed.', 'error');
    return;
  }
  const button = form.querySelector('button[type=submit]');
  button.disabled = true;
  try {
    const result = await api(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    render(result);
    say(`Saved ${result.saved.join(', ')}. The globe is restarting and will use the change in about 10 seconds.`, 'ok');
  } catch (error) {
    say(`Not saved: ${error.message}`, 'error');
  } finally {
    button.disabled = false;
  }
}

keyForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const updates = {};
  for (const input of keyForm.querySelectorAll('input[data-name]')) {
    if (input.value.trim()) updates[input.dataset.name] = input.value.trim();
  }
  for (const box of keyForm.querySelectorAll('input[data-remove]')) {
    if (box.checked) updates[box.dataset.remove] = null;
  }
  submit(keyForm, '/admin/api/keys', updates);
});

settingForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const updates = {};
  for (const input of settingForm.querySelectorAll('input[data-setting]:not([disabled])')) {
    const value = input.value.trim();
    if (input.type === 'password') {
      if (value) updates[input.dataset.setting] = value;
    } else if (value !== input.dataset.original) {
      updates[input.dataset.setting] = value || null;
    }
  }
  for (const box of settingForm.querySelectorAll('input[data-reset]')) {
    if (box.checked) updates[box.dataset.reset] = null;
  }
  submit(settingForm, '/admin/api/settings', updates);
});

load();
