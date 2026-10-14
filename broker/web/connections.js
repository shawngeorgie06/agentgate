'use strict';

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

const mounted = new WeakMap();

export async function renderConnections(container, api) {
  mounted.get(container)?.();
  let stopPolling = false;
  container.replaceChildren();
  const heading = element('h2', 'Connected services');
  const hint = element('p', 'Connections stay inside AgentGate. Agent requests are canceled when a connection changes.');
  const message = element('p', '', 'connection-message');
  message.setAttribute('role', 'status');
  const list = element('div');
  container.append(heading, hint, message, list);

  const post = (action, data = {}) => api(action, {
    method: 'POST', body: JSON.stringify(data),
  });

  function setMessage(text, failed = false) {
    message.textContent = text;
    message.classList.toggle('error', failed);
  }

  function renderService(service) {
    const card = element('article', undefined, 'card connection-card');
    const account = service.account?.email || service.account?.login || '';
    const header = element('div', undefined, 'card-head');
    header.append(element('h3', service.service === 'gmail' ? 'Gmail' : 'GitHub'));
    header.append(element('span', service.reconnecting ? 'Reconnecting' : service.status.replaceAll('_', ' '), 'pill'));
    card.append(header);
    card.append(element('p', account ? `Connected as ${account}` : (service.error || 'No account connected.')));
    const access = element('section', undefined, 'connection-agents');
    access.append(element('h4', 'Active agents and access'));
    const agents = service.agents || [];
    if (!agents.length) {
      access.append(element('p', 'No active enrolled agents.'));
    } else {
      for (const agent of agents) {
        const row = element('div', undefined, 'connection-agent');
        row.append(element('strong', agent.name));
        const rules = Object.entries(agent.permissions || {}).map(([resource, permission]) => `${resource}: ${permission}`).join(' · ');
        row.append(element('p', rules || 'No configured access.'));
        for (const grant of agent.temporary_grants || []) {
          row.append(element('p', `Temporary ${grant.permission} on ${grant.resource} until ${grant.expires_at}.`, 'hint'));
        }
        access.append(row);
      }
    }
    card.append(access);

    if (service.service === 'gmail') {
      const form = element('form', undefined, 'connection-form');
      const warning = element('p', 'Reconnecting may switch the Gmail account used by every agent on this broker.');
      warning.className = 'hint';
      const acknowledgeLabel = element('label');
      const acknowledge = element('input');
      acknowledge.type = 'checkbox';
      acknowledgeLabel.append(acknowledge, document.createTextNode(' I understand this may change the account used by all agents.'));
      const connect = element('button', 'Connect Gmail', 'primary');
      connect.type = 'submit';
      connect.disabled = true;
      acknowledge.addEventListener('change', () => { connect.disabled = !acknowledge.checked; });
      form.append(warning, acknowledgeLabel, connect);
      form.addEventListener('submit', async event => {
        event.preventDefault();
        connect.disabled = true;
        setMessage('Opening Google sign-in…');
        try {
          await post('gmail-reconnect');
          setMessage('Google sign-in started. This page will show the result when it finishes.');
          pollReconnect();
        } catch (error) {
          setMessage(error.message, true);
          connect.disabled = !acknowledge.checked;
        }
      });
      card.append(form);
      if (service.status !== 'disconnected') {
        card.append(button('Disconnect Gmail', 'danger', async event => disconnect('gmail', event)));
      }
    } else {
      const form = element('form', undefined, 'connection-form');
      const warning = element('p', 'Connecting a new token can replace the GitHub account used by every agent on this broker. Use a fine-grained token with repository Contents: read and Issues: read/write access.');
      warning.className = 'hint';
      const docs = element('a', 'GitHub fine-grained token instructions');
      docs.href = 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token';
      docs.target = '_blank';
      docs.rel = 'noopener noreferrer';
      const acknowledgeLabel = element('label');
      const acknowledge = element('input');
      acknowledge.type = 'checkbox';
      acknowledgeLabel.append(acknowledge, document.createTextNode(' I understand this may change the account used by all agents.'));
      const label = element('label', 'Fine-grained personal access token');
      const input = element('input');
      input.type = 'password';
      input.name = 'token';
      input.autocomplete = 'new-password';
      input.required = true;
      input.maxLength = 4096;
      label.append(input);
      const save = element('button', 'Connect GitHub', 'primary');
      save.type = 'submit';
      save.disabled = true;
      acknowledge.addEventListener('change', () => { save.disabled = !acknowledge.checked; });
      form.append(warning, docs, acknowledgeLabel, label, save);
      form.addEventListener('submit', async event => {
        event.preventDefault();
        save.disabled = true;
        const token = input.value;
        input.value = '';
        setMessage('Checking the GitHub token…');
        try {
          await post('github-connect', {token});
          setMessage('GitHub connected.');
          await refresh();
        } catch (error) {
          setMessage(error.message, true);
        } finally {
          save.disabled = !acknowledge.checked;
        }
      });
      card.append(form);
      if (service.status !== 'disconnected') {
        card.append(button('Disconnect GitHub', 'danger', async event => disconnect('github', event)));
      }
    }
    return card;
  }

  async function disconnect(service, event) {
    const label = service === 'gmail' ? 'Gmail' : 'GitHub';
    if (!window.confirm(`Remove the ${label} credentials from this broker? This is local only; it does not revoke the authorization at ${label}.`)) return;
    const control = event.currentTarget;
    control.disabled = true;
    setMessage(`Disconnecting ${label} locally…`);
    try {
      await post('connection-disconnect', {service});
      setMessage(`${label} disconnected.`);
      await refresh();
    } catch (error) {
      setMessage(error.message, true);
      control.disabled = false;
    }
  }

  async function pollReconnect() {
    if (stopPolling) return;
    try {
      const job = await api('reconnect-status');
      if (job.active) {
        setTimeout(pollReconnect, 700);
      } else {
        setMessage(job.state === 'completed' ? 'Gmail connected.' : (job.error || 'Gmail reconnect finished.'));
        await refresh();
      }
    } catch (error) {
      setMessage(error.message, true);
    }
  }

  async function refresh() {
    const result = await api('connections');
    list.replaceChildren(...result.services.map(renderService));
    return result;
  }

  container.append(button('Refresh connections', 'secondary', () => refresh().catch(e => setMessage(e.message, true))));
  await refresh();
  const destroy = () => { stopPolling = true; };
  mounted.set(container, destroy);
  return {refresh, destroy};
}
