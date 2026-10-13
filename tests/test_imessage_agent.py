import pytest
from broker.imessage_agent import ReadOnlyMessageAgent

class Model:
    def __init__(self, action='gmail_unread', **args):
        self.action, self.args, self.contexts, self.plans = action, args, [], []
    async def plan(self, prompt, history=''):
        self.plans.append(prompt)
        return {'action': self.action, **self.args}
    async def answer(self, prompt, context, history=''):
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
    async def answer(self, prompt, context, history=''):
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
        async def answer(self, prompt, context, history=''):
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
        async def answer(self, prompt, context, history=''):
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
