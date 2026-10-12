'use strict';

const POLL_MS = 2000;

function element(tag, text, className) {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = text;
  if (className) item.className = className;
  return item;
}

function button(text, className, handler) {
  const item = element('button', text, className);
  item.type = 'button';
  item.addEventListener('click', handler);
  return item;
}

function formatTime(value) {
  const date = new Date(value || '');
  return Number.isNaN(date.getTime()) ? (value || '—') : date.toLocaleString();
}

function expiryText(expiresAt) {
  const expiry = new Date(expiresAt || '').getTime();
  if (Number.isNaN(expiry)) return 'Expiry time unavailable.';
  const remaining = Math.ceil((expiry - Date.now()) / 1000);
  if (remaining <= 0) return 'This code has expired. Cancel and start pairing again.';
  const minutes = Math.floor(remaining / 60);
  const seconds = String(remaining % 60).padStart(2, '0');
  return `Expires in ${minutes}:${seconds}`;
}

// Human text for status error codes; unknown codes get a generic line rather than the raw code.
const ERROR_TEXT = {
  unavailable: 'iMessage is not available on this Mac.',
  not_paired: 'Pair an agent before turning iMessage on.',
  model_unavailable: 'The on-device model is unavailable.',
  pairing_expired: 'The pairing code expired. Start pairing again.',
  settings_unreadable: 'The iMessage settings could not be read.',
  settings_not_saved: 'The iMessage settings could not be saved.',
  loop_failed: 'iMessage lost its connection and is retrying.',
  agent_revoked: 'The paired agent was revoked. Pair an active agent to continue.',
  messages_database_changed: 'The Messages database changed. Re-pair to continue.',
  ledger_unavailable: 'The iMessage record could not be opened.',
  send_uncertain: 'A reply may or may not have been sent. It will not be retried automatically.',
  send_blocked: 'An earlier reply is still unresolved, so this reply was not sent.',
  send_failed: 'The iMessage helper could not send the reply.',
};

function errorText(code) {
  return ERROR_TEXT[code] || 'iMessage reported a problem. Refresh to check again.';
}

const mounted = new WeakMap();

export async function renderIMessage(container, api) {
  mounted.get(container)?.();
  container.replaceChildren();
  let destroyed = false;
  let rendered = false;
  let generation = 0;
  let pollTimer = null;
  let tickTimer = null;

  const post = (action, data = {}) => api(action, {
    method: 'POST', body: JSON.stringify(data),
  });

  const heading = element('div', undefined, 'section-heading');
  const refreshButton = button('↻ Refresh', '', () => load());
  heading.append(element('h2', 'iMessage'), refreshButton);
  const intro = element('p', 'Message yourself in Messages to ask an enrolled agent for help. Commands must start with "/agent ". The iMessage agent is read-only: sending email or creating GitHub issues still requires your approval in AgentGate.', 'hint');
  const message = element('p', '', 'imessage-message');
  message.setAttribute('role', 'status');
  message.hidden = true;
  const body = element('div');
  body.append(element('div', 'Loading iMessage status…', 'empty'));
  container.append(heading, intro, message, body);

  function setMessage(text = '', failed = false) {
    message.textContent = text;
    message.classList.toggle('error', failed);
    message.hidden = !text;
  }

  function stopTimers() {
    clearInterval(pollTimer);
    clearInterval(tickTimer);
    pollTimer = null;
    tickTimer = null;
  }

  // Runs one user action with its controls disabled, then reports the outcome.
  async function run(controls, work, success) {
    controls.forEach(control => { control.disabled = true; });
    setMessage('');
    try {
      await work();
      // A reload inside work() may have shown a broker error; never mask it with a success line.
      if (success && !message.classList.contains('error')) setMessage(success);
    } catch (error) {
      setMessage(error.message, true);
    } finally {
      controls.forEach(control => { control.disabled = false; });
    }
  }

  async function load() {
    const current = ++generation;
    refreshButton.disabled = true;
    try {
      const status = await api('imessage');
      if (destroyed || current !== generation) return;
      setMessage('');
      render(status);
    } catch (error) {
      if (destroyed || current !== generation) return;
      // Stop background polling on failure; the Refresh button restarts it.
      stopTimers();
      setMessage(error.message, true);
      // Keep the last good state visible; only replace the loading placeholder.
      if (!rendered) body.replaceChildren(element('div', 'iMessage status could not be loaded. Refresh to try again.', 'empty'));
    } finally {
      if (!destroyed && current === generation) refreshButton.disabled = false;
    }
  }

  function render(status) {
    stopTimers();
    rendered = true;
    body.replaceChildren();
    if (status.available && status.model && !status.model.available) {
      body.append(modelNotice(status.model.reason));
    }
    if (!status.available) body.append(unavailableView());
    // A paired agent keeps its controls even when iMessage is unavailable, so the user can still unpair.
    if (status.paired) body.append(pairedView(status));
    else if (status.available && status.pairing) body.append(pendingView(status.pairing));
    else if (status.available) body.append(unpairedView());
    body.append(recentView(Array.isArray(status.recent) ? status.recent : []));
    if (status.error) setMessage(errorText(status.error), true);
  }

  function modelNotice(reason) {
    return element('p', `The on-device model is unavailable${reason ? ': ' + reason : '.'} Replies need the model, so fix it before relying on iMessage.`, 'imessage-message error');
  }

  function unavailableView() {
    const card = element('article', undefined, 'card');
    card.append(element('h3', 'iMessage is not set up on this Mac'));
    card.append(element('p', 'Before iMessage can work, AgentGate needs its local helpers and two macOS permissions:', 'hint'));
    const steps = element('ol', undefined, 'hint');
    for (const step of [
      'Install the Messages helper and the on-device model helper, then restart AgentGate.',
      'In System Settings, Privacy & Security, allow AgentGate Full Disk Access to read the Messages database.',
      'Allow AgentGate Automation control of Messages to send replies.',
      'Come back here and refresh.',
    ]) steps.append(element('li', step));
    card.append(steps);
    return card;
  }

  function unpairedView() {
    const card = element('article', undefined, 'card');
    card.append(element('h3', 'Connect an agent'));
    card.append(element('p', 'Choose an active agent identity. Pairing gives you a one-time code to send from your own Messages thread; the code expires after a short time.', 'hint'));
    const form = element('form');
    const label = element('label', 'Agent');
    const select = element('select');
    select.name = 'agent_id';
    select.required = true;
    select.disabled = true;
    select.append(element('option', 'Loading agents…'));
    label.append(select);
    const start = element('button', 'Start pairing', 'primary');
    start.type = 'submit';
    start.disabled = true;
    form.append(label, start);
    form.addEventListener('submit', event => {
      event.preventDefault();
      run([start, select], async () => {
        await post('imessage-pair', {agent_id: select.value});
        await load();
      });
    });
    card.append(form);
    api('agents').then(data => {
      if (!card.isConnected) return;
      select.replaceChildren();
      if (!data.available) {
        select.append(element('option', 'Agent identity management is not configured.'));
        return;
      }
      const active = (data.agents || []).filter(agent => agent.status === 'active');
      if (!active.length) {
        select.append(element('option', 'No active agents'));
        card.append(element('p', 'Register an agent in Agents first.', 'hint'));
        return;
      }
      for (const agent of active) {
        const option = element('option', agent.name || agent.id);
        option.value = agent.id;
        select.append(option);
      }
      select.disabled = false;
      start.disabled = false;
    }).catch(error => {
      if (!card.isConnected) return;
      select.replaceChildren(element('option', 'Agents could not be loaded'));
      setMessage(error.message, true);
    });
    return card;
  }

  function pendingView(pairing) {
    const card = element('article', undefined, 'card');
    card.append(element('h3', 'Pairing in progress'));
    card.append(element('div', pairing.code, 'pair-code'));
    card.append(element('p', 'In Messages, start a conversation with yourself and send:', 'hint'));
    card.append(element('pre', `/agent pair ${pairing.code}`, 'command-example'));
    const expiry = element('p', expiryText(pairing.expires_at), 'hint');
    expiry.setAttribute('aria-live', 'polite');
    card.append(expiry);
    const cancel = button('Cancel pairing', '', () => run([cancel], async () => {
      await post('imessage-pair-cancel');
      await load();
    }, 'Pairing cancelled.'));
    card.append(cancel);
    const expiresAt = new Date(pairing.expires_at || '').getTime();
    if (expiresAt > Date.now()) {
      // Count down locally and poll the broker until the pairing finishes, is canceled, or expires.
      tickTimer = setInterval(() => {
        expiry.textContent = expiryText(pairing.expires_at);
        if (expiresAt <= Date.now()) stopTimers();
      }, 1000);
      pollTimer = setInterval(() => load(), POLL_MS);
    }
    return card;
  }

  function pairedView(status) {
    const name = status.agent?.name || status.agent?.id || 'an enrolled agent';
    const card = element('article', undefined, 'card');
    const head = element('div', undefined, 'card-head');
    let state = 'Off';
    if (status.enabled) state = status.running ? 'Running' : 'Enabled, not running';
    head.append(element('h3', status.enabled ? `Acting as ${name}` : `Paired with ${name}`), element('span', state, 'pill'));
    card.append(head);
    card.append(element('p', status.enabled
      ? 'Only messages you send to yourself that start with "/agent " are answered.'
      : 'iMessage is off. Turn it on to let the agent answer your "/agent " commands.', 'hint'));

    const actions = element('div', undefined, 'actions');
    const toggle = status.enabled
      ? button('Disable iMessage', '', () => run([toggle, unpairOpen], async () => {
          await post('imessage-disable');
          await load();
        }, 'iMessage disabled.'))
      : button('Enable iMessage', 'primary', () => run([toggle, unpairOpen], async () => {
          await post('imessage-enable');
          await load();
        }, 'iMessage enabled.'));
    // Turning on needs the helpers; turning off is always allowed.
    if (!status.enabled && !status.available) toggle.disabled = true;
    const unpairOpen = button('Unpair…', 'danger', () => {
      confirm.hidden = false;
      unpairOpen.hidden = true;
    });
    actions.append(toggle, unpairOpen);
    card.append(actions);

    // In-page confirmation before unpairing; the trigger hides while it is open.
    const confirm = element('div', undefined, 'imessage-confirm');
    confirm.hidden = true;
    confirm.append(element('p', `Unpair ${name}? iMessage will stop answering until you pair again.`));
    const keep = button('Keep paired', '', () => {
      confirm.hidden = true;
      unpairOpen.hidden = false;
    });
    const unpair = button('Unpair', 'danger', () => run([unpair, keep], async () => {
      await post('imessage-unpair');
      await load();
    }, 'iMessage unpaired.'));
    confirm.append(keep, unpair);
    card.append(confirm);
    return card;
  }

  function recentView(rows) {
    const section = element('section', undefined, 'connection-agents');
    section.append(element('h3', 'Recent activity'));
    if (!rows.length) {
      section.append(element('p', 'No iMessage requests yet.', 'empty'));
      return section;
    }
    for (const row of rows) {
      const item = element('div', undefined, 'activity-row');
      item.append(element('time', formatTime(row.claimed_at)));
      const times = element('div');
      times.append(element('small', row.attempted_at ? `Attempted ${formatTime(row.attempted_at)}` : 'Not attempted'));
      times.append(element('small', row.finished_at ? `Finished ${formatTime(row.finished_at)}` : 'Not finished'));
      item.append(times, element('b', String(row.status ?? 'unknown').replaceAll('_', ' ')));
      section.append(item);
    }
    return section;
  }

  const destroy = () => {
    destroyed = true;
    stopTimers();
  };
  mounted.set(container, destroy);
  await load();
  return {refresh: load, destroy};
}
