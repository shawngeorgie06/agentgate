'use strict';
const $ = id => document.getElementById(id);
const supplied = new URLSearchParams(location.hash.slice(1)).get('key');
if (supplied) { sessionStorage.setItem('agentgate-operator', supplied); history.replaceState(null, '', '/app'); }
const token = sessionStorage.getItem('agentgate-operator');
let nextDraftPage = null, draftsGeneration = 0;
let nextPage = null, pendingId = null, activeView = 'inbox', inboxGeneration = 0;
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
  $('view-title').textContent = {inbox:'Inbox', drafts:'Drafts', approvals:'Approvals', activity:'Activity'}[view];
  $('view-subtitle').textContent = {inbox:'A quieter place to work through your email.', drafts:'Thoughtful messages, ready when you are.', approvals:'Stay in control of every outgoing email.', activity:'See what your agents have been working on.'}[view];
  if (view === 'drafts') loadDrafts().catch(e => notice(e.message, true));
  if (view === 'activity') loadActivity().catch(e => notice(e.message, true));
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
  const card = node('article', undefined, 'card');
  const head = node('div', undefined, 'card-head'); head.append(node('h2', pending.preview ? pending.preview.subject || '(No subject)' : 'Access request'), node('span', 'Needs your approval', 'pill')); card.append(head);
  detail(card, 'Requested by', pending.agent); detail(card, 'Access', pending.credential);
  if (pending.preview) { if (pending.preview.from?.length) detail(card, 'From', pending.preview.from); preview(card, pending.preview, true); }
  const actions = node('div', undefined, 'actions');
  for (const approved of [true, false]) {
    const label = approved ? (pending.credential === 'gmail:send' ? 'Approve send' : 'Approve access') : 'Reject';
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
document.querySelectorAll('[data-view]').forEach(b => b.addEventListener('click', () => showView(b.dataset.view)));
$('search-form').addEventListener('submit', e => {e.preventDefault(); loadInbox().catch(e => notice(e.message, true));});
$('refresh-button').addEventListener('click', () => loadInbox().catch(e => notice(e.message, true)));
$('more-button').addEventListener('click', () => loadInbox(nextPage).catch(e => notice(e.message, true)));
$('draft-more-button').addEventListener('click', () => loadDrafts(nextDraftPage).catch(e => notice(e.message, true)));
$('draft-refresh').addEventListener('click', () => loadDrafts().catch(e => notice(e.message, true)));
$('activity-refresh').addEventListener('click', () => loadActivity().catch(e => notice(e.message, true)));
$('mode-button').addEventListener('click', async () => { try {await post('mode', {}); await pollStatus();} catch(e) {notice(e.message, true);} });
$('compose-button').addEventListener('click', () => { $('compose-form').reset(); $('compose-form').querySelector('[type=submit]').disabled = false; $('compose-dialog').showModal(); });
$('close-compose').addEventListener('click', () => $('compose-dialog').close());
$('compose-form').addEventListener('submit', async e => {
  e.preventDefault(); const button = e.target.querySelector('[type=submit]'); button.disabled = true;
  try { await post('draft', Object.fromEntries(new FormData(e.target))); $('compose-dialog').close(); notice('Draft saved to Gmail. Nothing has been sent.'); showView('drafts'); }
  catch(e) { notice(e.message + ' Check Gmail before saving again; the draft may have been created.', true); $('compose-dialog').close(); }
});
if (!token) { notice('Open AgentGate using the operator launcher to unlock this window.', true); empty($('message-list'), 'Waiting for operator access.'); $('compose-button').disabled = true; }
else { pollStatus(); loadInbox().catch(e => notice(e.message, true)); setInterval(pollStatus, 1500); }
