"""Open the operator app with sample mail only; no Google account is accessed."""
from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import sys
import tempfile
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from broker.config import Config
from broker.http_auth import create_token_file
from broker.integrations import gmail as module
from broker.main import run


class DemoService:
    def __init__(self):
        self.kind = 'messages'
        self.mail = {}
        self.draft_ids = []
        samples = [
            ('Avery Morgan <avery@example.test>', 'A quick check-in on the project', "Hi Shawn,\n\nThe next milestone is ready for your review. Could you take a look this week and let me know what you think?\n\nThanks,\nAvery"),
            ('Linear <updates@example.test>', 'Your weekly workspace update', 'Here is your weekly recap.\n\nThree tasks completed. Two new ideas ready to explore.\n\nHave a productive week!'),
            ('Jamie Chen <jamie@example.test>', 'Coffee next week?', 'Hey Shawn,\n\nWant to grab coffee Tuesday morning? Would love to catch up.\n\nJamie'),
        ]
        for i, (sender, subject, body) in enumerate(samples):
            message = EmailMessage(); message['From'] = sender; message['To'] = 'shawn@example.test'; message['Subject'] = subject
            message['Date'] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=i)
            message.set_content(body)
            self.mail[f'message-{i}'] = base64.urlsafe_b64encode(message.as_bytes()).decode()

    def users(self): return self
    def messages(self): self.kind = 'messages'; return self
    def drafts(self): self.kind = 'drafts'; return self
    def list(self, **kwargs):
        result = {'drafts':[{'id':i} for i in self.draft_ids]} if self.kind == 'drafts' else {'messages':[{'id':i} for i in self.mail if i.startswith('message-')]}
        return SimpleNamespace(execute=lambda: result)
    def get(self, id, **kwargs):
        message = {'id':id,'raw':self.mail[id],'threadId':id}
        result = {'id':id,'message':message} if self.kind == 'drafts' else message
        return SimpleNamespace(execute=lambda: result)
    def create(self, body, **kwargs):
        id = f'draft-{len(self.draft_ids)+1}'
        self.mail[id] = body['message']['raw']; self.draft_ids.append(id)
        return SimpleNamespace(execute=lambda: {'id':id})
    def send(self, **kwargs): return SimpleNamespace(execute=lambda: {'id':'demo-sent'})


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--port', type=int, default=8766); parser.add_argument('--no-open', action='store_true')
    args = parser.parse_args()
    fake = DemoService()
    # Override provider creation only in this sample-data process.
    original = module.Gmail.__init__
    def init(self, store, service_factory=None): original(self, store, service_factory=lambda: fake)
    module.Gmail.__init__ = init
    with tempfile.TemporaryDirectory(prefix='agentgate-app-demo-') as directory:
        root = Path(directory)
        for name in ('agent-token', 'operator-token'): create_token_file(str(root/name))
        # Public demo credential, only for sample data and visual verification.
        (root/'operator-token').write_text('agentgate-demo-operator-credential-123456\n')
        policies = root/'policies.yaml'
        policies.write_text('policies:\n  - name: demo\n    agent: agentgate-local\n    credential: "*"\n    auto_approve: true\n')
        config = Config.from_env({'POLICIES_PATH':str(policies),'STATE_PATH':str(root/'mode.json'),
                                 'LOGS_PATH':str(root/'audit.log'),'CREDENTIALS_PATH':str(root/'credentials.json'),
                                 'AGENTGATE_MASTER_PASSWORD':'demo-only','ESCALATION_TIMEOUT_SECONDS':'180'})
        print('AgentGate sample-data app; no Google account is accessed.', file=sys.stderr)
        asyncio.run(run(config, http=True, port=args.port, token_file=str(root/'agent-token'),
                        operator_token_file=str(root/'operator-token'), open_app=not args.no_open))

if __name__ == '__main__': main()
