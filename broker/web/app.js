'use strict';
const $ = id => document.getElementById(id);
const supplied = new URLSearchParams(location.hash.slice(1)).get('key');
if (supplied) { sessionStorage.setItem('agentgate-operator', supplied); history.replaceState(null, '', '/app'); }
const token = sessionStorage.getItem('agentgate-operator');
let nextDraftPage = null, draftsGeneration = 0;
let nextPage = null, pendingId = null, activeView = 'agents', inboxGeneration = 0;
let revokeAgentId = null, revokeAgentName = null;
function node(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
function notice(message, error = false) { $('notice').textContent = message; $('notice').classList.toggle('error', error); $('notice').hidden = !message; }
async function api(action, options = {}) {
  const response = await fetch('/api/' + action, { ...options, headers: { Authorization: 'Bearer ' + token, ...(options.body ? {'Content-Type': 'application/json'} : {}) } });
  const result = await response.json();
  if (!response.ok || !result.ok) throw new Error(result.reason || 'Request failed.');
  return result.data;
}
const post = (action, data) => api(action, {method: 'POST', body: JSON.stringify(data)});
function showView(view) {
  activeView = view;
  document.querySelectorAll('.view').forEach(n => n.hidden = n.id !== view + '-view');
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === view));
  $('compose-button').hidden = view === 'agents' || view === 'permissions';
  $('view-title').textContent = {inbox:'Inbox', drafts:'Drafts', approvals:'Approvals', activity:'Activity', agents:'Agents', permissions:'Permissions'}[view];
  $('view-subtitle').textContent = {inbox:'A quieter place to work through your email.', drafts:'Thoughtful messages, ready when you are.', approvals:'Stay in control of every outgoing email.', activity:'See what your agents have been working on.', agents:'Manage the identities that connect to your permission gateway.', permissions:'Decide what each agent can do with your connections.'}[view];
  if (view === 'drafts') loadDrafts().catch(e => notice(e.message, true));
  if (view === 'activity') loadActivity().catch(e => notice(e.message, true));
  if (view === 'permissions') loadPermissionAgents().catch(e => notice(e.message, true));
  if (view === 'agents') loadAgents().catch(e => notice(e.message, true));
  if (view === 'inbox') loadInbox().catch(e => notice(e.message, true));
}
function empty(target, text) { target.replaceChildren(node('div', text, 'empty')); }
function detail(target, label, value) { target.append(node('div', label, 'detail-label'), node('div', Array.isArray(value) ? value.join(', ') : (value || '—'), 'detail-value')); }
function bodyText(message) {
  const parts = message.parts || [];
  const plain = parts.filter(p => p.type === 'text/plain').map(p => p.content).join('\n');
  return plain || (parts.length ? 'HTML content (shown as source for safe review):\n\n' + parts.map(p => p.content).join('\n') : 'No text body.');
}
function preview(target, message, review = false) {
  detail(target, 'To', message.to); if (message.cc?.length) detail(target, 'Cc', message.cc); if (message.bcc?.length) detail(target, 'Bcc', message.bcc);
  target.append(node('pre', bodyText(message), 'email-body'));
  if (review && (message.parts || []).some(p => p.type === 'text/plain')) {
    for (const part of message.parts || []) {
      if (part.type !== 'text/plain') { detail(target, 'Additional version · ' + part.type, 'Shown as source for safe review'); target.append(node('pre', part.content, 'email-body')); }
    }
  }
  if (message.attachments?.length) detail(target, 'Attachments', message.attachments.map(a => (a.filename || 'Unnamed') + ' · ' + a.type).join('\n'));
}
async function loadInbox(pageToken = null) {
  const generation = ++inboxGeneration;
  empty($('message-list'), 'Loading your inbox…');
  $('more-button').hidden = true;
  const params = new URLSearchParams({query: $('search-query').value}); if (pageToken) params.set('page_token', pageToken);
  const data = await api('inbox?' + params);
  if (generation !== inboxGeneration) return;
  const list = $('message-list'); list.replaceChildren();
  nextPage = data.next_page_token; $('more-button').hidden = !nextPage;
  if (!data.messages.length) { empty(list, 'No messages match this search.'); return; }
  for (const message of data.messages) {
    const row = node('button', undefined, 'mail-row');
    const sender = node('div', undefined, 'sender'); sender.append(node('span', (message.from || []).join(', ') || 'Unknown sender'));
    const date = new Date(message.date); sender.append(node('time', Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString(undefined, {month:'short', day:'numeric'})));
    row.append(sender, node('div', message.subject || '(No subject)', 'subject'), node('div', message.snippet || 'Open to read this message', 'snippet'));
    row.addEventListener('click', () => {
      list.querySelectorAll('.mail-row').forEach(n => n.classList.remove('selected')); row.classList.add('selected');
      loadMessage(message.id).catch(e => notice(e.message, true));
    }); list.append(row);
  }
}
let readerGeneration = 0;
async function loadMessage(id) {
  const generation = ++readerGeneration;
  empty($('message-detail'), 'Loading message…');
  const message = await api('read?' + new URLSearchParams({id}));
  if (generation !== readerGeneration) return;
  const target = $('message-detail'); target.replaceChildren(node('h2', message.subject || '(No subject)'));
  const meta = node('div', undefined, 'message-meta'); detail(meta, 'From', message.from); detail(meta, 'Date', message.date); target.append(meta); preview(target, message);
}
async function loadDrafts(pageToken = null) {
  const generation = ++draftsGeneration;
  empty($('draft-list'), 'Loading drafts…');
  $('draft-more-button').hidden = true;
  const data = await api('drafts' + (pageToken ? '?' + new URLSearchParams({page_token:pageToken}) : ''));
  if (generation !== draftsGeneration) return;
  nextDraftPage = data.next_page_token; $('draft-more-button').hidden = !nextDraftPage;
  const list = $('draft-list'); list.replaceChildren();
  if (!data.drafts.length) { empty(list, 'No saved drafts. Start with “New draft”.'); return; }
  for (const draft of data.drafts) {
    const card = node('article', undefined, 'card'); card.append(node('h2', draft.subject || '(No subject)')); preview(card, draft);
    const button = node('button', draft.attempted ? 'Send already attempted' : 'Review & request send', 'primary'); button.disabled = draft.attempted;
    button.addEventListener('click', async () => {
      button.disabled = true; showView('approvals'); notice('Preparing your approval request…');
      try {
        const result = await post('send', {draft_id:draft.id});
        notice('Email sent. The original draft remains in Gmail.');
      } catch (e) { notice(e.message + ' Check Gmail and activity before another attempt; requests are never automatically retried.', true); }
      await pollStatus();
    }); card.append(button); list.append(card);
  }
}
function renderApproval(pending) {
  if ((pending?.id || null) === pendingId && $('approval-card').childNodes.length) return;
  pendingId = pending?.id || null;
  const target = $('approval-card'); target.replaceChildren();
  if (!pending) { empty(target, 'All clear. Agent requests that need your approval will appear here.'); return; }
  const isSend = pending.credential === 'gmail:send';
  const isPolicyChange = typeof pending.credential === 'string' && pending.credential.startsWith('policy.add:');
  const card = node('article', undefined, 'card');
  const title = isPolicyChange ? 'Policy change' : (isSend && pending.preview ? pending.preview.subject || '(No subject)' : 'Access request');
  const head = node('div', undefined, 'card-head'); head.append(node('h2', title), node('span', 'Needs your approval', 'pill')); card.append(head);
  detail(card, 'Requested by', pending.agent); detail(card, 'Access', pending.credential);
  if (isSend && pending.preview) {
    if (pending.preview.from?.length) detail(card, 'From', pending.preview.from);
    preview(card, pending.preview, true);
  } else if (pending.preview !== undefined && pending.preview !== null) {
    detail(card, isPolicyChange ? 'Policy proposal' : 'Request details', '');
    card.append(node('pre', JSON.stringify(pending.preview, null, 2), 'request-details'));
  }
  const actions = node('div', undefined, 'actions');
  for (const approved of [true, false]) {
    const label = approved ? (isSend ? 'Approve send' : (isPolicyChange ? 'Approve policy change' : 'Approve access')) : 'Reject';
    const button = node('button', label, approved ? 'primary' : 'danger');
    const id = pending.id;
    button.addEventListener('click', async () => {
      actions.querySelectorAll('button').forEach(b => b.disabled = true);
      try { await post('approval', {id, approved}); notice(approved ? 'Approved. Check activity for the result.' : 'Request rejected.'); }
      catch (e) { notice(e.message, true); }
      pendingId = null; await pollStatus();
    }); actions.append(button);
  }
  card.append(actions); target.append(card);
}
async function loadActivity() {
  const data = await api('activity'); const list = $('activity-list'); list.replaceChildren();
  if (!data.activity.length) { empty(list, 'Activity will appear as you and your agents work.'); return; }
  for (const row of data.activity) {
    const item = node('div', undefined, 'activity-row'); item.append(node('time', new Date(row.timestamp).toLocaleString()));
    const description = node('div', row.credential_requested); description.append(node('small', row.agent));
    item.append(description, node('b', row.decision)); list.append(item);
  }
}
async function loadAgents() {
  const list = $('agent-list'); empty(list, 'Loading enrolled identities…');
  const data = await api('agents'); list.replaceChildren();
  if (!data.available) { empty(list, 'Agent identity management is not configured for this broker.'); $('agent-form').querySelector('button[type=submit]').disabled = true; return; }
  $('agent-form').querySelector('button[type=submit]').disabled = false;
  if (!data.agents.length) { empty(list, 'No agents are enrolled yet. Register an identity when you are ready to connect an agent.'); return; }
  for (const agent of data.agents) {
    const card = node('article', undefined, 'card agent-card');
    const head = node('div', undefined, 'card-head'); head.append(node('h2', agent.name || agent.id));
    const status = node('span', agent.status || 'unknown', 'pill status-' + (agent.status || 'unknown')); head.append(status); card.append(head);
    detail(card, 'Identity', agent.id);
    detail(card, 'Created', formatDate(agent.created_at));
    detail(card, 'Expires', agent.expires_at ? formatDate(agent.expires_at) : 'No expiry (migrated credential)');
    if (agent.revoked_at) detail(card, 'Revoked', formatDate(agent.revoked_at));
    if (agent.status === 'active') {
      const button = node('button', 'Revoke access', 'danger');
      button.addEventListener('click', () => {
        revokeAgentId = agent.id; revokeAgentName = agent.name || agent.id;
        $('revoke-message').textContent = `Revoke ${revokeAgentName}? This agent will no longer be able to authenticate.`;
        $('revoke-dialog').showModal();
      }); card.append(button);
    }
    list.append(card);
  }
}
function formatDate(value) {
  const date = new Date(value || ''); return Number.isNaN(date.getTime()) ? (value || '—') : date.toLocaleString();
}
function showRegistrationResult(agent, credentialPath) {
  const result = $('registration-result'); result.replaceChildren(); result.hidden = false;
  const title = node('h2', 'Identity registered');
  const message = node('p', 'The credential was saved locally with private file permissions. Keep this path available to the agent process.');
  const pathLabel = node('div', 'Credential file', 'detail-label');
  const pathValue = node('div', credentialPath, 'credential-path');
  const commandLabel = node('div', 'Example agent command', 'detail-label');
  const quotedPath = "'" + credentialPath.replaceAll("'", "'\\''") + "'";
  const command = node('pre', `.venv/bin/python -m cli.agent --token-file ${quotedPath} status`, 'command-example');
  const copy = node('button', 'Copy command');
  copy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(command.textContent); notice('Example command copied.'); }
    catch (_) { notice('Copy is unavailable here. Select and copy the example command.', true); }
  });
  result.append(title, message, pathLabel, pathValue, commandLabel, command, copy);
}
async function registerAgent(event) {
  event.preventDefault(); const form = event.currentTarget; const button = form.querySelector('button[type=submit]');
  const values = new FormData(form); const ttl = Number(values.get('ttl_hours'));
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 8760) { notice('Lifetime must be a whole number from 1 to 8760 hours.', true); return; }
  button.disabled = true;
  try {
    const data = await post('agent-register', {name: values.get('name'), ttl_hours: ttl});
    showRegistrationResult(data.agent, data.credential_path); form.reset(); form.elements.ttl_hours.value = '720';
    notice('Identity registered. The credential is stored in the private credential folder.'); await loadAgents();
  } catch (e) { notice(e.message, true); }
  finally { button.disabled = false; }
}
let polling = false;
async function pollStatus() {
  if (polling) return; polling = true;
  try {
    const status = await api('status');
    $('connection-dot').classList.add('connected'); $('connection-label').textContent = 'Broker connected';
    $('gmail-status').textContent = status.demo ? 'Sample data' : (status.gmail_connected ? 'Connected' : 'Not connected');
    if (status.demo) document.querySelector('.workspace small').textContent = 'Demo · no live Gmail';
    $('pending-count').textContent = status.pending_count + (status.pending_count === 1 ? ' request' : ' requests');
    $('approval-badge').textContent = status.pending_count;
    $('mode-label').textContent = status.mode === 'auto' ? 'Trusted policies' : 'Ask every time';
    $('mode-caption').textContent = 'Click to change access mode'; renderApproval(status.pending);
  } catch (e) {
    $('connection-dot').classList.remove('connected'); $('connection-label').textContent = 'Disconnected';
    $('gmail-status').textContent = 'Unavailable'; notice(e.message + ' Keep the app broker running.', true);
  } finally { polling = false; }
}
let permissionRevision = null, permissionGeneration = 0, permissionProposal = null, permissionWindows = [];
async function loadPermissionAgents() {
  $('permissions-save').disabled = true; permissionRevision = null;
  const data = await api('agents'); const select = $('permission-agent'); const previous = select.value;
  select.replaceChildren();
  for (const agent of data.agents || []) {
    const option = node('option', agent.name + (agent.status === 'active' ? '' : ' · ' + agent.status));
    option.value = agent.id; option.disabled = agent.status !== 'active'; select.append(option);
  }
  const active = (data.agents || []).filter(a => a.status === 'active');
  if (!active.length) { notice('Register an active agent before setting permissions.', true); return; }
  select.value = active.some(a => a.id === previous) ? previous : active[0].id;
  await loadPermissions();
}
async function loadPermissions() {
  const generation = ++permissionGeneration; permissionRevision = null; $('permissions-save').disabled = true;
  const id = $('permission-agent').value;
  const data = await api('permissions?' + new URLSearchParams({agent_id:id}));
  if (generation !== permissionGeneration || $('permission-agent').value !== id) return;
  permissionWindows = data.time_windows || [];
  $('permission-windows').hidden = !permissionWindows.length;
  $('permission-windows').textContent = 'Existing time-window rules:\n' + permissionWindows.map(w => w.resource + ': ' + w.start + '–' + w.end + ' (' + w.policy + ')').join('\n') + '\nChoose each new all-time setting explicitly.';
  $('permission-window-ack-label').hidden = !permissionWindows.length;
  $('permission-window-ack').checked = false; $('permission-window-ack').required = !!permissionWindows.length;
  $('permission-read').value = permissionWindows.length ? '' : data.permissions['gmail:read'];
  $('permission-draft').value = permissionWindows.length ? '' : data.permissions['gmail:draft'];
  $('permission-send').value = permissionWindows.length ? '' : data.permissions['gmail:send'];
  permissionRevision = data.revision; $('permissions-save').disabled = data.agent.status !== 'active';
}
$('permission-agent').addEventListener('change', () => loadPermissions().catch(e => notice(e.message, true)));
$('permissions-refresh').addEventListener('click', () => loadPermissionAgents().catch(e => notice(e.message, true)));
$('permissions-form').addEventListener('submit', event => {
  event.preventDefault(); if (!permissionRevision) return;
  const permissions = {'gmail:read':$('permission-read').value,'gmail:draft':$('permission-draft').value,'gmail:send':$('permission-send').value};
  permissionProposal = {agent_id:$('permission-agent').value, permissions, revision:permissionRevision, acknowledge_time_windows: $('permission-window-ack').checked};
  const labels = {allow:'Allow without asking in AUTO mode', ask:'Ask me', deny:'Deny'};
  $('permissions-review').textContent = 'Agent: ' + permissionProposal.agent_id + '\nConnection: Gmail\nRules apply at all times; they replace earlier Gmail rules.\n' + (permissionWindows.length ? 'Existing windows explicitly acknowledged: ' + permissionWindows.map(w => w.resource + ' ' + w.start + '–' + w.end).join(', ') + '\n' : '') + '\nRead: ' + labels[permissions['gmail:read']] + '\nDraft: ' + labels[permissions['gmail:draft']] + '\nSend: ' + (permissions['gmail:send'] === 'ask' ? 'Ask before every send' : 'Deny');
  $('permissions-dialog').showModal();
});
$('permissions-cancel').addEventListener('click', () => {permissionProposal = null; $('permissions-dialog').close();});
$('permissions-confirm').addEventListener('click', async event => {
  if (!permissionProposal) return;
  const button = event.currentTarget; button.disabled = true;
  try {
    const data = await post('permissions', permissionProposal); permissionRevision = data.revision;
    $('permissions-dialog').close(); permissionProposal = null;
    notice('Permissions saved. Pending agent requests were cancelled.'); await pollStatus();
  } catch (error) {
    $('permissions-dialog').close(); permissionProposal = null; permissionRevision = null;
    $('permissions-save').disabled = true; notice(error.message + ' Reload rules before reviewing again.', true);
  } finally { button.disabled = false; }
});

document.querySelectorAll('[data-view]').forEach(b => b.addEventListener('click', () => showView(b.dataset.view)));
$('search-form').addEventListener('submit', e => {e.preventDefault(); loadInbox().catch(e => notice(e.message, true));});
$('refresh-button').addEventListener('click', () => loadInbox().catch(e => notice(e.message, true)));
$('more-button').addEventListener('click', () => loadInbox(nextPage).catch(e => notice(e.message, true)));
$('draft-more-button').addEventListener('click', () => loadDrafts(nextDraftPage).catch(e => notice(e.message, true)));
$('draft-refresh').addEventListener('click', () => loadDrafts().catch(e => notice(e.message, true)));
$('activity-refresh').addEventListener('click', () => loadActivity().catch(e => notice(e.message, true)));
$('agents-refresh').addEventListener('click', () => loadAgents().catch(e => notice(e.message, true)));
$('agent-form').addEventListener('submit', registerAgent);
$('confirm-revoke').addEventListener('click', async e => {
  e.preventDefault(); if (!revokeAgentId) return;
  const button = e.currentTarget; button.disabled = true;
  try { await post('agent-revoke', {id: revokeAgentId}); $('revoke-dialog').close(); notice(`Access revoked for ${revokeAgentName}.`); revokeAgentId = revokeAgentName = null; await loadAgents(); }
  catch (error) { notice(error.message, true); }
  finally { button.disabled = false; }
});
$('mode-button').addEventListener('click', async () => { try {await post('mode', {}); await pollStatus();} catch(e) {notice(e.message, true);} });
$('compose-button').addEventListener('click', () => { $('compose-form').reset(); $('compose-form').querySelector('[type=submit]').disabled = false; $('compose-dialog').showModal(); });
$('close-compose').addEventListener('click', () => $('compose-dialog').close());
$('compose-form').addEventListener('submit', async e => {
  e.preventDefault(); const button = e.target.querySelector('[type=submit]'); button.disabled = true;
  try { await post('draft', Object.fromEntries(new FormData(e.target))); $('compose-dialog').close(); notice('Draft saved to Gmail. Nothing has been sent.'); showView('drafts'); }
  catch(e) { notice(e.message + ' Check Gmail before saving again; the draft may have been created.', true); $('compose-dialog').close(); }
});
if (!token) { notice('Open AgentGate using the operator launcher to unlock this window.', true); empty($('message-list'), 'Waiting for operator access.'); $('compose-button').disabled = true; }
else { pollStatus(); loadAgents().catch(e => notice(e.message, true)); $('compose-button').hidden = true; setInterval(pollStatus, 1500); }
