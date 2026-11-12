import datetime as dt
import json

import pytest

from zoneinfo import ZoneInfo

from broker.imessage_agent import (DRAFT_TTL, DRAFT_WAITING, MessageAgent, _OTHER_REQUEST,
                                    _day_range, _day_start, _email_words)

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


@pytest.mark.parametrize('generated, request_text, saved', [
    ('Thank you for your response. I have already submitted the form. No further action is required at this time.',
     'Draft a reply to Taylor saying I already submitted the form', 'I have already submitted the form.'),
    ('Hello,\n\nThank you for your message. I will send the documents tomorrow.\n\nBest regards,',
     'Draft a reply to Taylor saying I will send the documents tomorrow',
     'Hello,\n\nI will send the documents tomorrow.'),
    ('Yes, I want to renew. Rent would go up by 50 dollars.',
     'Draft a reply to Taylor saying yes I want to renew', 'Yes, I want to renew.'),
    ('Friday works. Call me at 555-0100.', 'Draft a reply to Taylor saying Friday works', 'Friday works.'),
    ('See you at 3 p.m. on Friday. Looking forward to it.',
     'Draft a reply to Taylor saying see you at 3 p.m. on friday', 'See you at 3 p.m. on Friday.'),
    ('Thanks, I submitted the form.', 'Draft a reply to Taylor saying thanks, I submitted the form',
     'Thanks, I submitted the form.'),
    # A qualification stays with the sentence it qualifies.
    ('Friday works for me. But not if I have to be there. Thank you for your patience.',
     'Draft a reply to Taylor saying Friday works for me, but not if I have to be there',
     'Friday works for me. But not if I have to be there.'),
    ('Thanks. But I cannot. Best regards.', "Draft a reply to Taylor saying thanks, but I can't",
     'Thanks. But I cannot.'),
    # A line break inside a sentence is only wrapping.
    ('I have\nsubmitted the form.\n\nBest regards,\nSam', 'Draft a reply to Taylor saying I have submitted the form',
     'I have\nsubmitted the form.'),
    # A refusal made only of common words is kept even after padding.
    ('Hi Sam,\n\nThank you for the invitation. I cannot. Friday works instead.',
     "Draft a reply to Taylor saying I can't. Friday works instead.", 'Hi Sam,\n\nI cannot. Friday works instead.'),
    ('See you at 3 p.m.\n on Friday. Thank you for your time.',
     'Draft a reply to Taylor saying see you at 3 p.m. on friday', 'See you at 3 p.m.\n on Friday.'),
    ('I will take care of it. I will bring my car.', 'Draft a reply to Taylor saying I will take care of it',
     'I will take care of it.'),
    ('I am closing the account.', 'Draft a reply to Taylor saying I will close the account',
     'I am closing the account.'),
    ('Friday works. She refuses.', 'Draft a reply to Taylor saying Friday works. She will refuse.',
     'Friday works. She refuses.'),
    ('Thank you for your email. But I submitted the form.', 'Draft a reply to Taylor saying I submitted the form',
     'But I submitted the form.'),
    # Form and format are different words.
    ('I submitted the form. The format is correct.', 'Draft a reply to Taylor saying I submitted the form',
     'I submitted the form.'),
])
@pytest.mark.asyncio
async def test_sentences_the_user_did_not_ask_for_are_left_out_of_the_draft(generated, request_text, saved):
    tools = DraftTools()
    reply = await MessageAgent(None, tools, None, DraftModel(generated)).reply('reader', lambda: True, request_text)
    assert tools.created == [('reader', 'email-1', saved)]
    assert saved in reply and 'Draft saved' in reply


@pytest.mark.asyncio
async def test_reply_the_user_described_rather_than_worded_is_saved_whole():
    tools = DraftTools()
    body = 'Thank you for the invitation. I am not available this week.'
    await MessageAgent(None, tools, None, DraftModel(body)).reply(
        'reader', lambda: True, 'Draft a reply to Taylor saying decline politely')
    assert tools.created == [('reader', 'email-1', body)]


@pytest.mark.asyncio
async def test_words_that_only_name_the_email_do_not_count_as_reply_wording():
    tools = DraftTools()
    body = 'Thank you for the invitation. Unfortunately, I am unavailable.'
    await MessageAgent(None, tools, None, DraftModel(body)).reply(
        'reader', lambda: True, 'Draft a reply to Taylor about the invitation saying decline politely')
    assert tools.created == [('reader', 'email-1', body)]


@pytest.mark.asyncio
async def test_reply_wording_repeated_in_the_email_description_is_taken_after_the_saying_marker():
    class EchoModel(DraftModel):
        async def draft_request(self, prompt):
            return {'reply': 'Friday'}
    tools = DraftTools()
    await MessageAgent(None, tools, None, EchoModel('Friday. The interview sounds great.')).reply(
        'reader', lambda: True, 'Draft a reply to Taylor about the Friday interview saying Friday')
    assert tools.created == [('reader', 'email-1', 'Friday.')]


@pytest.mark.asyncio
async def test_wording_sent_as_a_later_text_decides_what_is_left_out():
    tools, model = DraftTools(), DraftModel('Thank you. I already submitted the form. Let me know if you need more.')
    agent = make_agent(tools, model)
    await agent.reply('reader', lambda: True, 'Draft a reply to Taylor about the interview')
    await agent.reply('reader', lambda: True, 'tell them I already submitted the form')
    assert tools.created == [('reader', 'email-1', 'I already submitted the form.')]


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


@pytest.mark.parametrize('text', [
    'list my github repos', 'List my GitHub repos.', 'show my repos', 'Show me my open issues',
    'check my unread email', 'never mind, check my unread email', 'Actually, can you check my inbox?',
    'please search my email for invoices', 'summarize my unread emails', 'how many unread emails do I have',
    'How many repos do I have?', 'do I have any new email', 'any new emails?', 'what is in my inbox',
    "what's in my inbox?", 'what are my repos', 'read the README in shawngeorgie06/agentgate',
    'list open issues in shawngeorgie06/agentgate', 'what can you do',
    'read the README.md in shawngeorgie06/agentgate', 'what repos do I have?', 'which repos do I own',
    'what can you do for me?', 'what unread email do I have', 'What can you do?', 'help',
])
def test_texts_addressed_to_the_assistant_are_recognised_as_other_requests(text):
    assert _OTHER_REQUEST.match(text)


@pytest.mark.parametrize('text', [
    'Friday works', 'I submitted the form yesterday', 'tell them thanks, I will pay by Friday', 'no thanks',
    'What time works for you?', 'Can I get an extension?', 'decline politely', 'Please send me the invoice again',
    'I can check my email tomorrow', 'ask them to list the charges', 'say I will search for the receipt',
    'I will look at the repo and get back to you', 'Please check your email for the invoice',
    'Are there any issues with the invoice?', 'Do I have to pay by Friday?', 'Can you help me with this?',
    'find the email from Taylor about the interview', 'the one from Taylor', 'Taylor, yesterday',
    'Please check and/or confirm the file', 'I read your email. My repo is public.', 'Thanks for your help.',
    'How many emails did you send?', 'Any news?', 'find the email from GitHub about my repositories',
    'search for the one about my repo', 'What issues do I have to fix?', 'read that email about my inbox', 'Get back to me about my email', 'I will get my email sorted', 'show me the invoice',
])
def test_reply_wording_and_email_descriptions_are_not_other_requests(text):
    assert not _OTHER_REQUEST.match(text)


@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['unsupported', 'chat', 'gmail_reply_draft'])
async def test_request_the_model_did_not_recognise_does_not_become_the_reply(action):
    tools, model = DraftTools(), DraftModel(action=action)
    agent = make_agent(tools, model)
    await agent.reply('reader', lambda: True, 'Draft a reply to Taylor')
    reply = await agent.reply('reader', lambda: True, 'list my github repos')
    assert not model.prompts and not tools.created
    assert reply.endswith(DRAFT_WAITING)
    model.action = 'chat'
    assert 'Draft saved' in await agent.reply('reader', lambda: True, 'Friday works')
    assert model.prompts == ['Friday works']


@pytest.mark.asyncio
async def test_search_request_while_naming_the_email_is_answered_instead_of_matched():
    tools, model = DraftTools(matches=[]), DraftModel(action='gmail_search')
    agent = make_agent(tools, model)
    await agent.reply('reader', lambda: True, 'Draft a reply')
    reply = await agent.reply('reader', lambda: True, 'search my email for invoices')
    assert tools.queries == ['from:taylor@example.test subject:interview']
    assert reply.endswith(DRAFT_WAITING)
    tools.matches = [{'id': 'email-1'}]
    assert 'What should the reply say?' in await agent.reply('reader', lambda: True, 'the one from Taylor')


@pytest.mark.asyncio
async def test_lookup_answered_beside_an_open_draft_says_the_draft_is_waiting():
    tools, model = DraftTools(), DraftModel(action='github_repos')
    agent = MessageAgent(None, tools, FailingGitHub(), model, clock=lambda: NOW, zone=EASTERN)
    assert DRAFT_WAITING not in await agent.reply('reader', lambda: True, 'what repos do I have')
    await agent.reply('reader', lambda: True, 'Draft a reply to Taylor')
    assert (await agent.reply('reader', lambda: True, 'what repos do I have')).endswith(DRAFT_WAITING)


@pytest.mark.asyncio
async def test_other_request_from_a_revoked_identity_drops_the_draft_without_a_reminder():
    active = [True]
    tools, model = DraftTools(), DraftModel()
    agent = make_agent(tools, model)
    await agent.reply('reader', lambda: active[0], 'Draft a reply to Taylor')
    active[0] = False
    reply = await agent.reply('reader', lambda: active[0], 'list my github repos')
    assert 'inactive' in reply and DRAFT_WAITING not in reply
    active[0] = True
    await agent.reply('reader', lambda: active[0], 'Friday works')
    assert not tools.created and not model.prompts


@pytest.mark.asyncio
async def test_other_request_after_the_draft_expired_gets_no_reminder():
    moment = [NOW]
    tools, model = DraftTools(), DraftModel(action='unsupported')
    agent = make_agent(tools, model, clock=lambda: moment[0])
    await agent.reply('reader', lambda: True, 'Draft a reply to Taylor')
    moment[0] = NOW + DRAFT_TTL
    assert DRAFT_WAITING not in await agent.reply('reader', lambda: True, 'list my github repos')


@pytest.mark.asyncio
async def test_draft_that_expires_while_another_request_is_answered_gets_no_reminder():
    moment = [NOW]

    class SlowModel(DraftModel):
        async def answer(self, prompt, context, history='', style=''):
            moment[0] = NOW + DRAFT_TTL
            return 'I can read accounts.'

    tools, model = DraftTools(), SlowModel(action='unsupported')
    agent = make_agent(tools, model, clock=lambda: moment[0])
    await agent.reply('reader', lambda: True, 'Draft a reply to Taylor')
    reply = await agent.reply('reader', lambda: True, 'list my github repos')
    assert reply == 'I can read accounts.'
