import datetime as dt
import json

import pytest

from zoneinfo import ZoneInfo

from broker.imessage_agent import DRAFT_TTL, MessageAgent, _day_range, _day_start, _email_words

EASTERN = dt.timezone(dt.timedelta(hours=-5))
NOW = dt.datetime(2026, 11, 11, 10, 0, tzinfo=EASTERN)  # a Wednesday


class DraftModel:
    def __init__(self, body='Friday works for me.', clarification='', action='chat'):
        self.body, self.clarification, self.action = body, clarification, action
        self.contexts, self.prompts = [], []

    async def plan(self, prompt, history=''):
        return {'action': self.action, 'query': 'from:taylor@example.test subject:interview', 'message_id': '',
                'owner': '', 'repo': '', 'path': '', 'ref': ''}

    async def draft_request(self, prompt):
        _, marker, said = prompt.partition(' saying ')
        return {'reply': said if marker else ''}

    async def draft_reply(self, prompt, context):
        self.prompts.append(prompt)
        self.contexts.append(json.loads(context))
        return {'body': self.body, 'clarification': self.clarification}


class DraftTools:
    """Gmail fake. `matches` is one listing for every search, or a function of the query."""

    def __init__(self, matches=None):
        self.matches = [{'id': 'email-1'}] if matches is None else matches
        self.calls, self.created = [], []

    @property
    def queries(self):
        return [call[3]['query'] for call in self.calls if call[2] == 'search']

    async def execute(self, agent, resource, operation, *, identity_guard, **args):
        assert identity_guard()
        self.calls.append((agent, resource, operation, args))
        if operation == 'search':
            matches = self.matches(args['query']) if callable(self.matches) else self.matches
            return {'ok': True, 'data': {'messages': matches}}
        assert operation == 'read'
        return {'ok': True, 'data': {'from': ['Taylor <taylor@example.test>'],
                                    'subject': 'Interview', 'text': 'Are you available Friday?',
                                    'date': 'Tue, 10 Nov 2026 09:30:00 -0500', 'raw': 'PRIVATE_RAW'}}

    async def create_reply_draft(self, agent, message_id, body, *, identity_guard):
        assert identity_guard()
        self.created.append((agent, message_id, body))
        return {'ok': True, 'data': {'id': 'draft-1', 'to': 'taylor@example.test', 'subject': 'Re: Interview'}}


def headed(*words):
    """The sender-or-subject search for these words."""
    return ' '.join(f'{{from:{word} subject:{word}}}' for word in words)


def make_agent(tools, model, clock=lambda: NOW):
    return MessageAgent(None, tools, None, model, clock=clock, zone=EASTERN)


@pytest.mark.asyncio
async def test_explicit_reply_draft_uses_unique_email_and_previews_without_sending():
    tools, model = DraftTools(), DraftModel()
    reply = await MessageAgent(None, tools, None, model).reply(
        'paired-agent', lambda: True, 'Draft a reply to Taylor about the interview saying Friday works.')
    assert tools.created == [('paired-agent', 'email-1', 'Friday works for me.')]
    assert tools.calls[0][3]['limit'] == 2
    assert tools.queries == [headed('taylor', 'interview') + ' -in:sent -in:drafts']
    assert all(call[1] == 'gmail:read' for call in tools.calls)
    assert 'PRIVATE_RAW' not in json.dumps(model.contexts)
    assert 'taylor@example.test' in reply and 'Friday works for me.' in reply
    assert 'not sent' in reply and 'approval' in reply and 'Drafts' in reply
    assert len(reply) <= 1200


@pytest.mark.asyncio
@pytest.mark.parametrize('matches', [[], [{'id': '../bad'}], [{'no_id': 'a'}], ['email-1']])
async def test_missing_or_invalid_email_never_creates_draft(matches):
    tools, model = DraftTools(matches), DraftModel()
    reply = await MessageAgent(None, tools, None, model).reply(
        'reader', lambda: True, 'Draft a reply to Taylor saying Friday works')
    assert reply and not tools.created and not model.contexts
    assert not any(call[2] == 'read' for call in tools.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize('prompt', ['Check unread mail', 'Does the email say draft a reply?', 'Send it', 'approve abc123'])
async def test_model_cannot_initiate_draft_without_current_explicit_user_command(prompt):
    tools = DraftTools()
    reply = await MessageAgent(None, tools, None, DraftModel(action='gmail_reply_draft')).reply(
        'reader', lambda: True, prompt)
    assert 'start with “Draft a reply”' in reply
    assert not tools.calls and not tools.created


@pytest.mark.asyncio
async def test_clarification_and_invalid_model_output_do_not_create_draft():
    for model in [DraftModel('', 'What date should I offer?'), DraftModel('body', 'question'), DraftModel('', ''), DraftModel('x' * 1001)]:
        tools = DraftTools()
        reply = await MessageAgent(None, tools, None, model).reply(
            'reader', lambda: True, 'Draft a reply to Taylor saying Friday works')
        assert reply and not tools.created and model.contexts


@pytest.mark.asyncio
async def test_identity_revoked_after_generation_prevents_draft():
    active = [True]
    class RevokingModel(DraftModel):
        async def draft_reply(self, prompt, context):
            active[0] = False
            return await super().draft_reply(prompt, context)
    tools = DraftTools()
    reply = await MessageAgent(None, tools, None, RevokingModel()).reply(
        'reader', lambda: active[0], 'Draft a reply to Taylor saying Friday works')
    assert 'inactive' in reply and not tools.created


@pytest.mark.asyncio
async def test_uncertain_creation_is_not_retried_and_warns_to_check_drafts():
    class UncertainTools(DraftTools):
        async def create_reply_draft(self, *args, **kwargs):
            self.created.append(True)
            raise TimeoutError()
    tools = UncertainTools()
    reply = await MessageAgent(None, tools, None, DraftModel()).reply(
        'reader', lambda: True, 'Draft a reply to Taylor saying Friday works')
    assert tools.created == [True]
    assert 'Check Gmail Drafts' in reply and 'nothing was sent' in reply


@pytest.mark.asyncio
async def test_model_cannot_save_invented_numeric_details():
    tools = DraftTools()
    reply = await MessageAgent(None, tools, None, DraftModel('My number is 123-456-7890.')).reply(
        'reader', lambda: True, 'Draft a reply to Taylor saying here is my phone number')
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


@pytest.mark.asyncio
async def test_newest_of_several_matches_is_used_and_named():
    tools = DraftTools([{'id': 'newest'}, {'id': 'older'}])
    reply = await make_agent(tools, DraftModel()).reply(
        'reader', lambda: True, 'Draft a reply to Taylor saying Friday works')
    assert tools.created == [('reader', 'newest', 'Friday works for me.')]
    assert 'newest of several matching emails' in reply


@pytest.mark.asyncio
async def test_request_can_be_finished_over_several_texts():
    tools, model = DraftTools(), DraftModel()
    agent = make_agent(tools, model)
    first = await agent.reply('reader', lambda: True, 'Draft a reply')
    assert 'Which email' in first and not tools.calls
    second = await agent.reply('reader', lambda: True, 'the one from Taylor about the interview')
    assert 'Replying to Taylor — “Interview” (Nov 10)' in second and 'What should the reply say?' in second
    assert not tools.created and not model.prompts
    third = await agent.reply('reader', lambda: True, 'tell them Friday works')
    assert 'Draft saved' in third and tools.created == [('reader', 'email-1', 'Friday works for me.')]
    assert model.prompts == ['tell them Friday works']
    assert tools.queries == [headed('taylor', 'interview') + ' -in:sent -in:drafts']


@pytest.mark.asyncio
async def test_wording_given_first_is_kept_until_the_email_is_named():
    tools, model = DraftTools(), DraftModel()
    agent = make_agent(tools, model)
    assert 'Which email' in await agent.reply('reader', lambda: True, 'Can you draft a reply saying Friday works')
    reply = await agent.reply('reader', lambda: True, 'Taylor interview')
    assert 'Draft saved' in reply and model.prompts == ['Can you draft a reply saying Friday works']


@pytest.mark.asyncio
async def test_clarification_keeps_the_draft_open_for_the_missing_detail():
    tools, model = DraftTools(), DraftModel('', 'What time works for you?')
    agent = make_agent(tools, model)
    reply = await agent.reply('reader', lambda: True, 'Draft a reply to Taylor saying I can meet')
    assert reply == ('No draft created yet. What time works for you?\n'
                     'Your next text continues this draft. Text “cancel” to stop.')
    model.body, model.clarification = 'I can meet at 3.', ''
    reply = await agent.reply('reader', lambda: True, 'at 3')
    assert 'Draft saved' in reply and tools.created
    assert model.prompts[-1] == 'Draft a reply to Taylor saying I can meet\nat 3'
    assert len(tools.queries) == 1


@pytest.mark.asyncio
async def test_dates_become_local_day_filters_and_never_search_words():
    tools = DraftTools()
    await make_agent(tools, DraftModel()).reply(
        'reader', lambda: True, 'draft a reply for the AWS email I received yesterday nov 10 saying thanks')
    first = int(dt.datetime(2026, 11, 10, tzinfo=EASTERN).timestamp())
    assert tools.queries == [f'{headed("aws")} after:{first - 1} before:{first + 86400} -in:sent -in:drafts']


@pytest.mark.asyncio
async def test_looser_match_needs_confirmation_before_drafting():
    tools = DraftTools(lambda query: [{'id': 'email-1'}] if query.startswith('aws -in') else [])
    model = DraftModel()
    agent = make_agent(tools, model)
    reply = await agent.reply('reader', lambda: True, 'Draft a reply to aws certification support saying thanks')
    assert 'did not find an exact match' in reply and 'Text “yes”' in reply
    tail = ' -in:sent -in:drafts'
    assert tools.queries == [headed('aws', 'certification', 'support') + tail, 'aws certification support' + tail,
                             headed('aws', 'certification') + tail, 'aws certification' + tail,
                             headed('aws') + tail, 'aws' + tail]
    assert not tools.created and not model.prompts
    reply = await agent.reply('reader', lambda: True, 'Yes')
    assert 'Draft saved' in reply and tools.created == [('reader', 'email-1', 'Friday works for me.')]


@pytest.mark.asyncio
async def test_declined_closest_match_asks_again_and_date_only_needs_confirmation():
    tools = DraftTools()
    agent = make_agent(tools, DraftModel())
    reply = await agent.reply('reader', lambda: True, 'Draft a reply to the email from yesterday saying thanks')
    assert 'did not find an exact match' in reply
    assert 'Which email' in await agent.reply('reader', lambda: True, 'no')
    assert not tools.created


@pytest.mark.asyncio
async def test_date_is_dropped_only_as_a_last_resort():
    tools = DraftTools(lambda query: [] if 'after:' in query else [{'id': 'email-1'}])
    reply = await make_agent(tools, DraftModel()).reply('reader', lambda: True, 'Draft a reply to Taylor from yesterday')
    assert 'did not find an exact match' in reply
    assert tools.queries[-1] == headed('taylor') + ' -in:sent -in:drafts' and len(tools.queries) == 3


@pytest.mark.asyncio
async def test_cancel_and_idle_timeout_forget_the_draft():
    tools, model = DraftTools(), DraftModel()
    agent = make_agent(tools, model)
    await agent.reply('reader', lambda: True, 'Draft a reply to Taylor')
    assert 'Nothing was created' in await agent.reply('reader', lambda: True, 'never mind')
    await agent.reply('reader', lambda: True, 'tell them Friday works')
    assert not tools.created and not model.prompts

    moment = [NOW]
    agent = make_agent(tools, model, clock=lambda: moment[0])
    await agent.reply('reader', lambda: True, 'Draft a reply to Taylor')
    moment[0] = NOW + DRAFT_TTL
    await agent.reply('reader', lambda: True, 'tell them Friday works')
    assert not tools.created and not model.prompts

    await agent.reply('reader', lambda: True, 'Draft a reply to Taylor')
    agent.forget()
    await agent.reply('reader', lambda: True, 'tell them Friday works')
    assert not tools.created and not model.prompts


@pytest.mark.asyncio
async def test_another_lookup_does_not_consume_the_pending_draft():
    tools, model = DraftTools(), DraftModel(action='github_repos')
    agent = MessageAgent(None, tools, FailingGitHub(), model, clock=lambda: NOW, zone=EASTERN)
    await agent.reply('reader', lambda: True, 'Draft a reply to Taylor')
    await agent.reply('reader', lambda: True, 'what repos do I have')
    assert not model.prompts and not tools.created
    model.action = 'chat'
    assert 'Draft saved' in await agent.reply('reader', lambda: True, 'Friday works')


@pytest.mark.asyncio
async def test_pending_draft_belongs_to_the_agent_that_started_it():
    tools, model = DraftTools(), DraftModel()
    agent = make_agent(tools, model)
    await agent.reply('reader', lambda: True, 'Draft a reply to Taylor')
    await agent.reply('other', lambda: True, 'Friday works')
    assert not tools.created and not model.prompts


@pytest.mark.asyncio
async def test_identity_revoked_between_texts_stops_the_draft():
    active = [True]
    tools, model = DraftTools(), DraftModel()
    agent = make_agent(tools, model)
    await agent.reply('reader', lambda: active[0], 'Draft a reply to Taylor')
    active[0] = False
    assert 'inactive' in await agent.reply('reader', lambda: active[0], 'Friday works')
    active[0] = True
    await agent.reply('reader', lambda: active[0], 'Friday works')
    assert not tools.created and not model.prompts


@pytest.mark.asyncio
async def test_a_topic_is_never_mistaken_for_the_reply_wording():
    class TopicModel(DraftModel):
        async def draft_request(self, prompt):
            return {'reply': 'regarding AWS certification support'}
    tools, model = DraftTools(), TopicModel()
    reply = await make_agent(tools, model).reply(
        'reader', lambda: True, 'Draft a reply for the email regarding AWS certification support')
    assert 'What should the reply say?' in reply and not model.prompts
    assert tools.queries == [headed('aws', 'certification', 'support') + ' -in:sent -in:drafts']


@pytest.mark.asyncio
async def test_split_falls_back_to_the_users_wording_when_the_model_fails():
    class BrokenModel(DraftModel):
        async def draft_request(self, prompt):
            raise RuntimeError('helper failed')
    tools, model = DraftTools(), BrokenModel()
    reply = await make_agent(tools, model).reply('reader', lambda: True, 'Draft a reply to Taylor saying Friday works')
    assert 'Draft saved' in reply and tools.queries == [headed('taylor') + ' -in:sent -in:drafts']


class FailingGitHub:
    async def execute(self, *args, **kwargs):
        return {'ok': False}


@pytest.mark.parametrize('text, expected', [
    ('yesterday', (dt.date(2026, 11, 10), dt.date(2026, 11, 11))),
    ('today', (dt.date(2026, 11, 11), dt.date(2026, 11, 12))),
    ('NOV 10', (dt.date(2026, 11, 10), dt.date(2026, 11, 11))),
    ('november 10th, 2025', (dt.date(2025, 11, 10), dt.date(2025, 11, 11))),
    ('10 nov', (dt.date(2026, 11, 10), dt.date(2026, 11, 11))),
    ('dec 25', (dt.date(2025, 12, 25), dt.date(2025, 12, 26))),
    ('11/9', (dt.date(2026, 11, 9), dt.date(2026, 11, 10))),
    ('11/9/25', (dt.date(2025, 11, 9), dt.date(2025, 11, 10))),
    ('on monday', (dt.date(2026, 11, 9), dt.date(2026, 11, 10))),
    ('last wednesday', (dt.date(2026, 11, 4), dt.date(2026, 11, 5))),
    ('this week', (dt.date(2026, 11, 9), dt.date(2026, 11, 12))),
    ('last week', (dt.date(2026, 11, 2), dt.date(2026, 11, 9))),
    ('feb 30', None), ('13/45', None), ('the may release', None), ('ticket 4/5/6/7', None), ('Taylor', None),
])
def test_day_ranges(text, expected):
    assert _day_range(text, NOW.date()) == expected


def test_email_words_are_the_users_own_keywords_without_operators():
    assert _email_words('Draft a reply to the email from Dana Lee about the lease renewal on nov 10') == (
        ['dana', 'lee', 'lease', 'renewal'], True)
    assert _email_words('from this address aws-cs-noreply@support.aws.com') == (['aws-cs-noreply@support.aws.com'], True)
    assert _email_words('(from:boss OR in:sent) -in:inbox {label:x}') == (['boss', 'label'], True)
    words, complete = _email_words(' '.join(f'word{n}' for n in range(30)))
    assert len(words) == 8 and not complete


def test_day_start_follows_the_daylight_saving_rule_of_that_day():
    new_york = ZoneInfo('America/New_York')
    assert _day_start(dt.date(2026, 7, 1), new_york) == int(dt.datetime(2026, 7, 1, 4, tzinfo=dt.timezone.utc).timestamp())
    assert _day_start(dt.date(2026, 11, 10), new_york) == int(dt.datetime(2026, 11, 10, 5, tzinfo=dt.timezone.utc).timestamp())
    # With no zone the Mac's own rules apply, the same as a naive local midnight.
    assert _day_start(dt.date(2026, 7, 1), None) == int(dt.datetime(2026, 7, 1).timestamp())


@pytest.mark.asyncio
async def test_summer_date_asked_in_winter_uses_summer_offset_and_utc_clock():
    tools = DraftTools()
    utc_now = NOW.astimezone(dt.timezone.utc)
    agent = MessageAgent(None, tools, None, DraftModel(), clock=lambda: utc_now, zone=ZoneInfo('America/New_York'))
    await agent.reply('reader', lambda: True, 'Draft a reply to Taylor from july 1 saying thanks')
    first = int(dt.datetime(2026, 7, 1, 4, tzinfo=dt.timezone.utc).timestamp())
    assert tools.queries == [f'{headed("taylor")} after:{first - 1} before:{first + 86400} -in:sent -in:drafts']


@pytest.mark.asyncio
async def test_description_longer_than_the_search_limit_needs_confirmation():
    tools, model = DraftTools(), DraftModel()
    reply = await make_agent(tools, model).reply(
        'reader', lambda: True,
        'Draft a reply about alpha bravo charlie delta echo foxtrot golf hotel approved saying thanks')
    assert 'did not find an exact match' in reply and not tools.created and not model.prompts
    assert tools.queries == [headed(*'alpha bravo charlie delta echo foxtrot golf hotel'.split()) + ' -in:sent -in:drafts']


@pytest.mark.asyncio
async def test_wording_the_user_did_not_type_is_never_used_as_reply_content():
    class InventingModel(DraftModel):
        async def draft_request(self, prompt):
            return {'reply': 'Thanks for reaching out.'}
    tools, model = DraftTools(), InventingModel()
    reply = await make_agent(tools, model).reply('reader', lambda: True, 'Draft a reply to Taylor about the interview')
    assert 'What should the reply say?' in reply and not tools.created and not model.prompts
    assert tools.queries == [headed('taylor', 'interview') + ' -in:sent -in:drafts']


@pytest.mark.asyncio
@pytest.mark.parametrize('while_inactive', ['Draft a reply to Dana', 'check my unread email'])
async def test_any_text_seen_while_inactive_drops_the_pending_draft(while_inactive):
    active = [True]
    tools, model = DraftTools(), DraftModel(action='gmail_unread')
    agent = make_agent(tools, model)
    await agent.reply('reader', lambda: active[0], 'Draft a reply to Taylor')
    active[0] = False
    assert 'inactive' in await agent.reply('reader', lambda: active[0], while_inactive)
    active[0] = True
    model.action = 'chat'
    await agent.reply('reader', lambda: active[0], 'Friday works')
    assert not tools.created and not model.prompts


@pytest.mark.asyncio
async def test_sender_or_subject_match_beats_a_newer_email_that_only_mentions_the_word():
    def matches(query):
        if query.startswith('{from:aws subject:aws} after:'):
            return [{'id': 'email-1'}]
        return [{'id': 'newsletter'}, {'id': 'email-1'}]
    tools = DraftTools(matches)
    agent = make_agent(tools, DraftModel())
    reply = await agent.reply('paired-agent', lambda: True, 'Draft a reply to the AWS email from yesterday')
    assert reply.startswith('Replying to') and 'several' not in reply
    assert len(tools.queries) == 1 and [call[3] for call in tools.calls if call[2] == 'read'] == [{'message_id': 'email-1'}]


@pytest.mark.asyncio
async def test_words_found_only_in_the_body_still_match_exactly():
    tools = DraftTools(lambda query: [] if query.startswith('{') else [{'id': 'email-1'}])
    agent = make_agent(tools, DraftModel())
    reply = await agent.reply('paired-agent', lambda: True, 'Draft a reply to the email about parking')
    assert reply.startswith('Replying to')
    assert tools.queries == [headed('parking') + ' -in:sent -in:drafts', 'parking -in:sent -in:drafts']


@pytest.mark.asyncio
async def test_one_text_with_the_request_on_three_lines_finds_the_email_and_drafts():
    tools, model = DraftTools(), DraftModel()
    reply = await make_agent(tools, model).reply(
        'paired-agent', lambda: True, 'Draft a reply\nthe AWS email from yesterday\ntell them I already submitted the form')
    first = int(dt.datetime(2026, 11, 10, tzinfo=EASTERN).timestamp())
    assert tools.queries == [f'{headed("aws")} after:{first - 1} before:{first + 86400} -in:sent -in:drafts']
    assert 'Draft saved' in reply and len(tools.created) == 1


@pytest.mark.asyncio
async def test_a_date_alone_is_searched_once_and_needs_confirmation():
    tools = DraftTools()
    reply = await make_agent(tools, DraftModel()).reply('paired-agent', lambda: True, 'Draft a reply to the email from yesterday')
    assert 'did not find an exact match' in reply and len(tools.queries) == 1
    assert tools.queries[0].startswith('after:')


@pytest.mark.asyncio
async def test_more_pages_of_results_count_as_several_matches():
    class Paged(DraftTools):
        async def execute(self, agent, resource, operation, *, identity_guard, **args):
            result = await super().execute(agent, resource, operation, identity_guard=identity_guard, **args)
            if operation == 'search':
                result['data']['nextPageToken'] = 'more'
            return result
    reply = await make_agent(Paged(), DraftModel()).reply('paired-agent', lambda: True, 'Draft a reply to Taylor')
    assert 'newest of several matches' in reply
