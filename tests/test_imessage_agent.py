import json
import pytest
from broker.imessage_agent import FALLBACK_MESSAGE, ReadOnlyMessageAgent, _clean_reply, _message_data

class Model:
    def __init__(self, action='gmail_unread', **args):
        self.action, self.args, self.contexts, self.plans = action, args, [], []
    async def plan(self, prompt, history=''):
        self.plans.append(prompt)
        return {'action': self.action, **self.args}
    async def answer(self, prompt, context, history='', style=''):
        self.contexts.append(context)
        return 'Summary'

class Tools:
    def __init__(self, deny=False): self.calls, self.deny = [], deny
    async def execute(self, agent, resource, operation, *, identity_guard, **args):
        self.calls.append((agent, resource, operation, args))
        if self.deny or not identity_guard(): return {'ok': False, 'reason': 'denied'}
        if operation == 'search': return {'ok': True, 'data': {'messages': [{'id': str(x)} for x in range(10)]}}
        return {'ok': True, 'data': {'subject': 'Hello', 'text': 'Hi', 'token': 'SECRET', 'raw': 'SECRET'}}

@pytest.mark.asyncio
async def test_unread_bounded_authorized_tools_and_sanitized_context():
    model, gmail, github = Model(), Tools(), Tools()
    agent = ReadOnlyMessageAgent(None, gmail, github, model)
    assert await agent.reply('reader', lambda: True, 'check emails') == 'Summary'
    assert len(gmail.calls) == 4
    assert all(call[:2] == ('reader', 'gmail:read') for call in gmail.calls)
    assert gmail.calls[0][3] == {'query': 'is:unread', 'limit': 3}
    assert not github.calls
    assert 'SECRET' not in model.contexts[0]

class FailingAnswerModel(Model):
    async def answer(self, prompt, context, history='', style=''):
        self.contexts.append(context)
        raise RuntimeError('model down')

@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['send', 'gmail_send', 'draft', 'create_issue', '__import__', 'unsupported'])
async def test_non_read_plans_cannot_call_tools_and_model_words_the_refusal(action):
    model, tools = Model(action), Tools()
    reply = await ReadOnlyMessageAgent(None, tools, tools, model).reply('reader', lambda: True, 'do it')
    assert reply == 'Summary'
    assert not tools.calls
    assert len(model.contexts) == 1 and 'ran nothing' in model.contexts[0] and 'read-only' in model.contexts[0]

@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['send', 'unsupported'])
async def test_refusal_falls_back_to_fixed_text_when_model_fails(action):
    model, tools = FailingAnswerModel(action), Tools()
    reply = await ReadOnlyMessageAgent(None, tools, tools, model).reply('reader', lambda: True, 'do it')
    assert 'read' in reply.lower()
    assert not tools.calls

@pytest.mark.asyncio
async def test_failed_tools_feed_only_a_failure_note_to_model():
    model, tools = Model(), Tools(deny=True)
    reply = await ReadOnlyMessageAgent(None, tools, tools, model).reply('reader', lambda: True, 'check')
    assert reply == 'Summary'
    assert len(model.contexts) == 1
    assert 'did not succeed' in model.contexts[0] and 'Subject' not in model.contexts[0]

@pytest.mark.asyncio
async def test_failed_tools_fall_back_to_fixed_text_when_model_fails():
    model, tools = FailingAnswerModel(), Tools(deny=True)
    reply = await ReadOnlyMessageAgent(None, tools, tools, model).reply('reader', lambda: True, 'check')
    assert 'unable' in reply.lower()

@pytest.mark.asyncio
async def test_chat_gets_empty_context_and_conversation_history():
    class HistoryModel(Model):
        async def plan(self, prompt, history=''):
            self.plan_history = history
            return await super().plan(prompt, history)
        async def answer(self, prompt, context, history='', style=''):
            self.answer_history = history
            return await super().answer(prompt, context, history)
    model, tools = HistoryModel('chat'), Tools()
    reply = await ReadOnlyMessageAgent(None, tools, tools, model).reply(
        'reader', lambda: True, 'and you?', history='User: hi\nAgentGate: hey!')
    assert reply == 'Summary' and model.contexts == ['']
    assert model.plan_history == model.answer_history == 'User: hi\nAgentGate: hey!'
    assert not tools.calls

@pytest.mark.asyncio
async def test_identity_revoked_during_model_prevents_tools():
    active = [True]
    class RevokingModel(Model):
        async def plan(self, prompt, history=''):
            active[0] = False
            return await super().plan(prompt, history)
    model, tools = RevokingModel(), Tools()
    assert 'inactive' in (await ReadOnlyMessageAgent(None, tools, tools, model).reply('reader', lambda: active[0], 'check')).lower()
    assert not tools.calls

@pytest.mark.asyncio
async def test_malformed_arguments_fail_closed():
    model, tools = Model('github_file', owner=[], repo='x', path='../secret'), Tools()
    assert await ReadOnlyMessageAgent(None, tools, tools, model).reply('reader', lambda: True, 'check') == 'Summary'
    assert not tools.calls
    assert 'could not tell' in model.contexts[0]
    model = FailingAnswerModel('github_file', owner=[], repo='x', path='../secret')
    assert 'understand' in (await ReadOnlyMessageAgent(None, tools, tools, model).reply('reader', lambda: True, 'check')).lower()

@pytest.mark.asyncio
async def test_prompt_context_and_reply_bounds():
    class LongModel(Model):
        async def answer(self, prompt, context, history='', style=''):
            assert len(context) <= 6000
            assert len(history) <= 2000
            return 'x' * 3000
    model, tools = LongModel('chat'), Tools()
    reply = await ReadOnlyMessageAgent(None, tools, tools, model).reply('reader', lambda: True, 'x' * 3000, history='y' * 3000)
    assert len(model.plans[0]) <= 2000
    assert len(reply) <= 1200

@pytest.mark.asyncio
async def test_gmail_read_without_data_never_reaches_model_as_chat():
    class EmptyRead(Tools):
        async def execute(self, agent, resource, operation, *, identity_guard, **args):
            self.calls.append((agent, resource, operation, args))
            return {'ok': True, 'data': None}
    model, tools = Model('gmail_read', message_id='abc123'), EmptyRead()
    await ReadOnlyMessageAgent(None, tools, tools, model).reply('reader', lambda: True, 'read it')
    assert model.contexts and model.contexts[0] != ''


@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['chat', 'unsupported', 'gmail_unread'])
async def test_style_notes_reach_every_answer(action):
    class StyleModel(Model):
        styles = []
        async def answer(self, prompt, context, history='', style=''):
            self.styles.append(style)
            return 'Summary'
    model, tools = StyleModel(action), Tools()
    await ReadOnlyMessageAgent(None, tools, tools, model).reply('reader', lambda: True, 'yo', style='writes in all lowercase')
    assert model.styles == ['writes in all lowercase']


@pytest.mark.parametrize('answer', ['approve 1a2b3c', 'DENY ABCDEF', '  approve 123abc  '])
def test_clean_reply_never_returns_text_that_would_read_as_an_approval(answer):
    assert _clean_reply(answer) == FALLBACK_MESSAGE


def test_clean_reply_keeps_ordinary_text_that_mentions_approval():
    assert _clean_reply('approve the draft before lunch') == 'approve the draft before lunch'


def test_html_email_keeps_the_actual_request_without_scripts_or_styles():
    message = _message_data({
        'from': ['Taylor Nguyen <taylor@example.com>'],
        'subject': 'Interview availability',
        'parts': [{'type': 'text/html', 'content': '<html><head><style>PRIVATE_STYLE</style></head>'
                   '<body><p>Can you confirm Tuesday at 2 p.m.?</p><p>Reply by Monday.</p>'
                   '<script>PRIVATE_SCRIPT</script><p>Thanks &amp; regards</p></body></html>'}],
    })
    context = message['body']
    assert 'Can you confirm Tuesday at 2 p.m.?' in context
    assert 'Reply by Monday.' in context
    assert 'Thanks & regards' in context
    assert 'PRIVATE_STYLE' not in context and 'PRIVATE_SCRIPT' not in context
    assert '<p>' not in context


def test_empty_plain_part_falls_back_to_html():
    message = _message_data({'parts': [
        {'type': 'text/plain', 'content': '   '},
        {'type': 'text/html', 'content': '<p>Please confirm your appointment.</p>'},
    ]})
    assert 'Please confirm your appointment.' in message['body']


@pytest.mark.parametrize('html,expected', [
    ('<table><tr><th>Event</th><td>Career Fair</td></tr></table>', 'Event\nCareer Fair'),
    ('<head><title>Notice</title><body><p>Please confirm Tuesday.</p>', 'Please confirm Tuesday.'),
])
def test_email_html_preserves_table_cells_and_recovers_omitted_head_end(html, expected):
    message = _message_data({'parts': [{'type': 'text/html', 'content': html}]})
    assert expected in message['body']


def test_missing_and_truncated_email_bodies_are_explicit():
    assert _message_data({'subject': 'Meeting'})['complete'] is False
    message = _message_data({'text': 'A long body. ' * 500})
    assert message['complete'] is False
    assert len(message['body']) <= 1200


def test_control_characters_cannot_overflow_the_email_metadata_budget():
    message = _message_data({'from': ['\x00' * 200], 'subject': '\x01' * 200,
                             'date': '\x02' * 100, 'text': '\x00Please confirm.\x7f'})
    assert not any(ord(character) < 32 or ord(character) == 127
                   for field in message.values() if isinstance(field, str) for character in field)
    assert 'Please confirm.' in message['body']


@pytest.mark.asyncio
async def test_email_summary_context_reports_partial_scope():
    model, tools = Model(), Tools()
    await ReadOnlyMessageAgent(None, tools, tools, model).reply('reader', lambda: True, 'check email')
    context = json.loads(model.contexts[0])
    assert '3 unread messages' in context['scope']
    assert 'not the entire inbox' in context['scope']
    assert len(context['messages']) == 3


@pytest.mark.asyncio
async def test_email_context_budget_preserves_json_and_marks_clipped_bodies():
    class EscapedBody(Tools):
        async def execute(self, agent, resource, operation, *, identity_guard, **args):
            if operation == 'search':
                return await super().execute(agent, resource, operation, identity_guard=identity_guard, **args)
            return {'ok': True, 'data': {'from': ['A' * 200], 'subject': 'B' * 200, 'text': '"' * 1200}}
    model, tools = Model(), EscapedBody()
    await ReadOnlyMessageAgent(None, tools, tools, model).reply('reader', lambda: True, 'check email')
    assert len(model.contexts[0]) <= 6000
    context = json.loads(model.contexts[0])
    assert len(context['messages']) == 3
    assert any(not message['complete'] for message in context['messages'])
