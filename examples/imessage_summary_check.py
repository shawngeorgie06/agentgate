"""Inspect actual local-model replies using synthetic email, without sending messages.

Run with python -m examples.imessage_summary_check --helper /path/to/agentgate-model.
"""
import argparse
import asyncio

from broker.apple_model import AppleModel
from broker.imessage_agent import ReadOnlyMessageAgent
from broker.imessage_service import AsyncAppleModel


MESSAGES = [
    {'from': ['Metro Live Shows <news@example.com>'],
     'subject': 'Bon Jovi concert announced for September',
     'parts': [{'type': 'text/html', 'content': '<p>Bon Jovi is coming to Metro Stadium.</p>'
                '<p>Tickets go on sale Friday at 10 a.m. This is a concert announcement. '
                'This mailbox is not monitored.</p>'}]},
    {'from': ['Harbor Bank Careers <careers@example.com>'],
     'subject': 'Two upcoming career information sessions',
     'parts': [{'type': 'text/plain', 'content': 'Join our summer internship information session '
                'on Tuesday or our graduate analyst Q&A on Thursday. Registration is optional; '
                'no reply is requested.'}]},
    {'from': ['Taylor Nguyen <taylor@example.com>'],
     'subject': 'Please confirm your interview time',
     'parts': [{'type': 'text/html', 'content': '<p>Can you confirm whether Tuesday at 2 p.m. '
                'works for your interview? Please reply by Monday.</p>'}]},
]


class SampleGmail:
    def __init__(self, messages):
        self.messages = messages

    async def execute(self, agent, resource, operation, *, identity_guard, **arguments):
        if not identity_guard() or resource != 'gmail:read':
            raise AssertionError('The sample only allows Gmail reads.')
        if operation == 'search':
            return {'ok': True, 'data': {'messages': [{'id': str(i)} for i in range(len(self.messages))]}}
        if operation == 'read':
            return {'ok': True, 'data': self.messages[int(arguments['message_id'])]}
        raise AssertionError('The sample must never mutate data.')


async def main(helper):
    model = AsyncAppleModel(AppleModel(helper))
    style = 'very short texts (about 4 words); writes in all lowercase; rarely ends with a period; often says lol, u'
    cases = [
        ('Mixed announcements and a direct reply request', MESSAGES),
        ('Missing body', [{'from': ['Taylor Nguyen'], 'subject': 'Interview availability'}]),
        ('Truncated body', [{'from': ['Harbor Bank Careers'], 'subject': 'Career events',
                             'text': 'Information about career events. ' * 100}]),
        ('Reply request in a recruiter excerpt', [{'from': ['Taylor Nguyen'], 'subject': 'Interview slots',
            'parts': [{'type': 'text/html', 'content':
                '<p>Could you reply by Friday with your availability for a Tuesday phone interview?</p>'
                + '<p>Our internship program includes mentoring and team projects.</p>' * 40}]}]),
    ]
    for name, messages in cases:
        agent = ReadOnlyMessageAgent(None, SampleGmail(messages), None, model)
        reply = await agent.reply('sample-reader', lambda: True,
                                  'Check my unread emails and tell me which need a reply', style=style)
        print(f'\n{name}\n{reply}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', required=True)
    asyncio.run(main(parser.parse_args().helper))
