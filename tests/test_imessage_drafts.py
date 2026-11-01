import json

import pytest

from broker.imessage_agent import MessageAgent


class DraftModel:
    def __init__(self, body='Friday works for me.', clarification=''):
        self.body, self.clarification = body, clarification
        self.contexts = []

    async def plan(self, prompt, history=''):
        return {'action': 'gmail_reply_draft', 'query': 'from:taylor@example.test subject:interview'}

    async def draft_reply(self, prompt, context):
        self.contexts.append(json.loads(context))
        return {'body': self.body, 'clarification': self.clarification}


class DraftTools:
    def __init__(self, matches=None):
        self.matches = [{'id': 'email-1'}] if matches is None else matches
        self.calls, self.created = [], []

    async def execute(self, agent, resource, operation, *, identity_guard, **args):
        assert identity_guard()
        self.calls.append((agent, resource, operation, args))
        if operation == 'search':
            return {'ok': True, 'data': {'messages': self.matches}}
        assert operation == 'read'
        return {'ok': True, 'data': {'from': ['Taylor <taylor@example.test>'],
                                    'subject': 'Interview', 'text': 'Are you available Friday?',
                                    'raw': 'PRIVATE_RAW'}}

    async def create_reply_draft(self, agent, message_id, body, *, identity_guard):
        assert identity_guard()
        self.created.append((agent, message_id, body))
        return {'ok': True, 'data': {'id': 'draft-1', 'to': 'taylor@example.test', 'subject': 'Re: Interview'}}


@pytest.mark.asyncio
async def test_explicit_reply_draft_uses_unique_email_and_previews_without_sending():
    tools, model = DraftTools(), DraftModel()
    reply = await MessageAgent(None, tools, None, model).reply(
        'paired-agent', lambda: True, 'Draft a reply to Taylor about the interview saying Friday works.')
    assert tools.created == [('paired-agent', 'email-1', 'Friday works for me.')]
    assert tools.calls[0][3]['limit'] == 2
    assert tools.calls[0][3]['query'].endswith(' -in:sent -in:drafts')
    assert all(call[1] == 'gmail:read' for call in tools.calls)
    assert 'PRIVATE_RAW' not in json.dumps(model.contexts)
    assert 'taylor@example.test' in reply and 'Friday works for me.' in reply
    assert 'not sent' in reply and 'approval' in reply and 'Drafts' in reply
    assert len(reply) <= 1200


@pytest.mark.asyncio
@pytest.mark.parametrize('matches', [[], [{'id': 'a'}, {'id': 'b'}], [{'id': '../bad'}]])
async def test_missing_ambiguous_or_invalid_email_never_creates_draft(matches):
    tools, model = DraftTools(matches), DraftModel()
    reply = await MessageAgent(None, tools, None, model).reply('reader', lambda: True, 'Draft a reply to Taylor')
    assert reply and not tools.created and not model.contexts


@pytest.mark.asyncio
@pytest.mark.parametrize('prompt', ['Check unread mail', 'Does the email say draft a reply?', 'Send it', 'approve abc123'])
async def test_model_cannot_initiate_draft_without_current_explicit_user_command(prompt):
    tools = DraftTools()
    await MessageAgent(None, tools, None, DraftModel()).reply('reader', lambda: True, prompt)
    assert not tools.calls and not tools.created


@pytest.mark.asyncio
async def test_clarification_and_invalid_model_output_do_not_create_draft():
    for model in [DraftModel('', 'What date should I offer?'), DraftModel('body', 'question'), DraftModel('', ''), DraftModel('x' * 1001)]:
        tools = DraftTools()
        reply = await MessageAgent(None, tools, None, model).reply('reader', lambda: True, 'Draft a reply to Taylor')
        assert reply and not tools.created


@pytest.mark.asyncio
async def test_identity_revoked_after_generation_prevents_draft():
    active = [True]
    class RevokingModel(DraftModel):
        async def draft_reply(self, prompt, context):
            active[0] = False
            return await super().draft_reply(prompt, context)
    tools = DraftTools()
    reply = await MessageAgent(None, tools, None, RevokingModel()).reply('reader', lambda: active[0], 'Draft a reply to Taylor')
    assert 'inactive' in reply and not tools.created


@pytest.mark.asyncio
async def test_uncertain_creation_is_not_retried_and_warns_to_check_drafts():
    class UncertainTools(DraftTools):
        async def create_reply_draft(self, *args, **kwargs):
            self.created.append(True)
            raise TimeoutError()
    tools = UncertainTools()
    reply = await MessageAgent(None, tools, None, DraftModel()).reply('reader', lambda: True, 'Draft a reply to Taylor')
    assert tools.created == [True]
    assert 'Check Gmail Drafts' in reply and 'nothing was sent' in reply


@pytest.mark.asyncio
async def test_model_cannot_save_invented_numeric_details():
    tools = DraftTools()
    reply = await MessageAgent(None, tools, None, DraftModel('My number is 123-456-7890.')).reply(
        'reader', lambda: True, 'Draft a reply to Taylor giving my phone number')
    assert 'No draft created' in reply and 'exact numbers' in reply
    assert not tools.created


@pytest.mark.asyncio
async def test_explicitly_supplied_number_can_be_used_in_draft():
    tools = DraftTools()
    reply = await MessageAgent(None, tools, None, DraftModel('Call me on 555-0100.')).reply(
        'reader', lambda: True, 'Draft a reply to Taylor saying call me on 555-0100')
    assert 'Draft saved' in reply and tools.created


@pytest.mark.asyncio
async def test_known_pre_creation_rejection_is_clear_and_not_uncertain():
    class InvalidSource(DraftTools):
        async def create_reply_draft(self, *args, **kwargs):
            return {'ok': False, 'code': 'draft_not_created', 'reason': 'The source must have one unambiguous reply address.'}
    reply = await MessageAgent(None, InvalidSource(), None, DraftModel()).reply(
        'reader', lambda: True, 'Draft a reply to Taylor saying Friday works')
    assert 'No draft was created:' in reply and 'unambiguous reply address' in reply
    assert 'Check Gmail Drafts' not in reply and 'could not be confirmed' not in reply
