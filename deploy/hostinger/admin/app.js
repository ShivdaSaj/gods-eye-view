// Admin key editor. Builds every node with DOM APIs; no HTML from data.
const list = document.getElementById('list');
const form = document.getElementById('keys');
const notice = document.getElementById('notice');
const save = document.getElementById('save');

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

function render(keys) {
  list.replaceChildren(
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
        el('p', { class: 'muted' }, entry.unlocks, ' · ',
          el('a', { href: entry.getUrl, target: '_blank', rel: 'noopener noreferrer' }, 'Get a key')),
        ...entry.vars.map((variable) =>
          el(
            'div',
            { class: 'var' },
            el(
              'label',
              { for: `in-${variable.name}` },
              el('code', {}, variable.name),
              el('span', { class: `badge ${variable.set ? 'on' : 'off'}` }, variable.set ? 'Set' : 'Not set'),
            ),
            el('input', {
              id: `in-${variable.name}`,
              'data-name': variable.name,
              type: 'password',
              spellcheck: 'false',
              autocomplete: 'off',
              placeholder: variable.set ? 'Paste a new value to replace it' : 'Paste the key',
            }),
            variable.set
              ? el(
                  'label',
                  { class: 'remove' },
                  el('input', { type: 'checkbox', 'data-remove': variable.name }),
                  ' Remove',
                )
              : null,
          ),
        ),
      ),
    ),
  );
}

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

async function load() {
  try {
    render((await api('/admin/api/status')).keys);
  } catch (error) {
    say(`Could not load keys: ${error.message}`, 'error');
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const updates = {};
  for (const input of form.querySelectorAll('input[data-name]')) {
    if (input.value.trim()) updates[input.dataset.name] = input.value.trim();
  }
  for (const box of form.querySelectorAll('input[data-remove]')) {
    if (box.checked) updates[box.dataset.remove] = null;
  }
  if (!Object.keys(updates).length) {
    say('Nothing to save: paste a key or tick Remove.', 'error');
    return;
  }
  save.disabled = true;
  try {
    const result = await api('/admin/api/keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    render(result.keys);
    say(`Saved ${result.saved.join(', ')}. The globe is restarting and will pick them up in about 10 seconds.`, 'ok');
  } catch (error) {
    say(`Not saved: ${error.message}`, 'error');
  } finally {
    save.disabled = false;
  }
});

load();
