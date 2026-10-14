export async function renderGrants(container, api) {
  const make = (tag, text, className) => {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  };
  const field = (labelText, control) => {
    const label = make('label', labelText);
    label.append(control);
    return label;
  };
  const post = (action, value) => api(action, {
    method: 'POST',
    body: JSON.stringify(value),
  });

  container.replaceChildren();
  const heading = make('div', undefined, 'section-heading');
  heading.append(make('h2', 'Temporary access'), make('button', '↻ Refresh'));
  const refresh = heading.querySelector('button');
  refresh.type = 'button';
  const intro = make('p', 'A temporary grant overrides the matching baseline permission until it expires or you revoke it. After expiry, the saved policy applies again.', 'hint');
  const notice = make('p');
  notice.setAttribute('role', 'status');
  const formCard = make('article', undefined, 'card');
  formCard.append(make('h2', 'Grant temporary access'));
  const form = document.createElement('form');
  const agent = document.createElement('select'); agent.required = true; agent.name = 'agent_id';
  const resource = document.createElement('select'); resource.required = true; resource.name = 'resource';
  for (const [value, label] of [
    ['gmail:read', 'Gmail · Read'], ['gmail:draft', 'Gmail · Draft'], ['gmail:send', 'Gmail · Send'],
    ['github:read', 'GitHub · Read'], ['github:write', 'GitHub · Write'],
  ]) {
    const option = make('option', label); option.value = value; resource.append(option);
  }
  const permission = document.createElement('select'); permission.required = true; permission.name = 'permission';
  const minutes = document.createElement('input'); minutes.type = 'number'; minutes.min = '1'; minutes.max = '1440'; minutes.step = '1'; minutes.value = '60'; minutes.required = true; minutes.name = 'minutes';
  const reason = document.createElement('input'); reason.type = 'text'; reason.maxLength = 500; reason.name = 'reason'; reason.placeholder = 'Optional';
  const permissionChoices = () => {
    permission.replaceChildren();
    const write = resource.value === 'gmail:send' || resource.value === 'github:write';
    for (const [value, label] of write ? [['ask', 'Ask me each time']] : [['allow', 'Allow in AUTO mode'], ['ask', 'Ask me each time']]) {
      const option = make('option', label); option.value = value; permission.append(option);
    }
  };
  resource.addEventListener('change', permissionChoices);
  permissionChoices();
  form.append(
    field('Agent', agent), field('Resource', resource), field('Temporary permission', permission),
    field('Lifetime in minutes', minutes), field('Reason', reason),
  );
  const submit = make('button', 'Review grant', 'primary'); submit.type = 'submit'; form.append(submit);
  formCard.append(form);
  const historyCard = make('article', undefined, 'card');
  historyCard.append(make('h2', 'Grant history'));
  const history = make('div');
  historyCard.append(history);
  const dialog = document.createElement('dialog');
  const dialogTitle = make('h2');
  const dialogReview = make('pre', undefined, 'command-example');
  const actions = make('div', undefined, 'dialog-actions');
  const cancel = make('button', 'Cancel'); cancel.type = 'button';
  const confirm = make('button', 'Confirm', 'primary'); confirm.type = 'button';
  actions.append(cancel, confirm); dialog.append(dialogTitle, dialogReview, actions);
  container.append(heading, intro, notice, formCard, historyCard, dialog);

  let agents = [];
  let pendingAction = null;
  const showNotice = (message, error = false) => { notice.textContent = message; notice.className = error ? 'error' : 'hint'; };
  const openReview = (title, body, label, action) => {
    pendingAction = action;
    dialogTitle.textContent = title;
    dialogReview.textContent = body;
    confirm.textContent = label;
    confirm.className = label.toLowerCase().includes('revoke') ? 'danger' : 'primary';
    dialog.showModal();
  };
  cancel.addEventListener('click', () => { pendingAction = null; dialog.close(); });
  confirm.addEventListener('click', async () => {
    if (!pendingAction) return;
    const action = pendingAction; pendingAction = null; confirm.disabled = true;
    try {
      await action(); dialog.close(); await load();
    } catch (error) { dialog.close(); showNotice(error.message || 'The grant could not be changed.', true); }
    finally { confirm.disabled = false; }
  });

  const load = async () => {
    showNotice('');
    const [agentData, grantData] = await Promise.all([api('agents'), api('grants')]);
    agents = agentData.agents || [];
    const selected = agent.value;
    agent.replaceChildren();
    for (const item of agents.filter(row => row.status === 'active')) {
      const option = make('option', item.name || item.id); option.value = item.id; agent.append(option);
    }
    if (selected && [...agent.options].some(option => option.value === selected)) agent.value = selected;
    formCard.hidden = !grantData.available;
    if (!grantData.available) showNotice('Temporary access management is unavailable for this broker.', true);
    const rows = grantData.grants || [];
    history.replaceChildren();
    if (!rows.length) history.append(make('p', 'No temporary grants have been created.', 'empty'));
    for (const grant of [...rows].reverse()) {
      const card = make('article', undefined, 'activity-row');
      const description = make('div');
      const agentInfo = agents.find(item => item.id === grant.agent_id);
      description.append(make('strong', `${agentInfo?.name || grant.agent_id} · ${grant.resource}`));
      description.append(make('small', `${grant.permission === 'allow' ? 'Allow in AUTO mode' : 'Ask each time'} · ${grant.reason || 'No reason provided'}`));
      description.append(make('small', `Created ${format(grant.created_at)} · Expires ${format(grant.expires_at)} · baseline policy resumes at expiry`));
      card.append(description, make('b', grant.status));
      if (grant.status === 'active') {
        const revoke = make('button', 'Revoke', 'danger'); revoke.type = 'button';
        revoke.addEventListener('click', () => openReview(
          'Revoke temporary access?',
          `${agentInfo?.name || grant.agent_id}\n${grant.resource} · ${grant.permission}\nExpires ${format(grant.expires_at)}\n${grant.reason || 'No reason provided'}`,
          'Revoke grant',
          async () => { await post('grant-revoke', {grant_id: grant.id}); showNotice('Temporary grant revoked.'); },
        ));
        card.append(revoke);
      }
      history.append(card);
    }
  };
  const format = value => {
    const date = new Date(value || '');
    return Number.isNaN(date.getTime()) ? (value || '—') : date.toLocaleString();
  };
  form.addEventListener('submit', event => {
    event.preventDefault();
    const ttl = Number(minutes.value);
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > 1440) { showNotice('Lifetime must be a whole number from 1 to 1440 minutes.', true); return; }
    const values = {agent_id: agent.value, resource: resource.value, permission: permission.value, minutes: ttl, reason: reason.value};
    const agentInfo = agents.find(item => item.id === values.agent_id);
    if (!agentInfo || agentInfo.status !== 'active') { showNotice('Choose an active enrolled agent.', true); return; }
    const expiry = new Date(Date.now() + ttl * 60000).toLocaleString();
    openReview('Review temporary grant',
      `${agentInfo.name || agentInfo.id}\n${values.resource} · ${values.permission}\n${ttl} minutes · expires around ${expiry}\nAfter expiry, the saved baseline policy applies.\nReason: ${values.reason || 'None provided'}`,
      'Create grant',
      async () => { await post('grant-create', values); showNotice('Temporary grant created.'); form.reset(); minutes.value = '60'; permissionChoices(); },
    );
  });
  refresh.addEventListener('click', () => load().catch(error => showNotice(error.message, true)));
  await load();
  return {reload: load};
}
