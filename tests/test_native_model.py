"""Verify deterministic email-rendering rules in the actual on-device helper."""
import json
import platform
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from broker.apple_model import AppleModel


pytestmark = pytest.mark.skipif(
    sys.platform != 'darwin' or shutil.which('swiftc') is None
    or int((platform.mac_ver()[0] or '0').split('.')[0]) < 26,
    reason='The native model helper requires macOS 26 and Swift.',
)


@pytest.fixture(scope='module')
def local_model(tmp_path_factory):
    directory = tmp_path_factory.mktemp('native-model')
    helper = directory / 'agentgate-model'
    source = Path(__file__).resolve().parents[1] / 'native/AgentGateModel.swift'
    subprocess.run([shutil.which('swiftc'), '-parse-as-library', str(source), '-o', str(helper),
                    '-framework', 'Foundation', '-framework', 'FoundationModels'], check=True,
                   capture_output=True, timeout=120)
    helper.chmod(0o700)
    model = AppleModel(helper)
    result = model.availability()
    if result.get('ok') and not result['data']['available']:
        pytest.skip('Apple Intelligence is unavailable on this Mac.')
    assert result.get('ok')
    return model


@pytest.mark.parametrize('body,limitation', [('', 'Body unavailable'), ('An announcement...', 'Body truncated')])
def test_incomplete_body_cannot_get_a_guessed_reply_recommendation(local_model, body, limitation):
    context = json.dumps({'kind': 'email_review', 'scope': 'Checked 1 requested email.', 'messages': [
        {'sender': 'Taylor Nguyen', 'subject': 'Interview availability', 'date': '',
         'body': body, 'complete': False},
    ]})
    result = local_model.answer('Which emails need a reply?', context, style='often says lol, u')
    assert result.get('ok')
    text = result['data']['text']
    assert text.startswith('Checked 1 requested email.')
    assert 'Taylor Nguyen:' in text
    if not body:
        assert 'Interview availability' in text
    assert limitation in text
    if body:
        assert "can't determine whether a reply is needed" in text
    else:
        assert "can't answer questions" in text
    assert 'No reply' not in text and 'lol' not in text


def test_specific_email_question_answers_requested_detail(local_model):
    context = json.dumps({'kind': 'email_review', 'scope': 'Checked 1 requested email.', 'messages': [
        {'sender': 'Maple Hotel', 'subject': 'Your stay details', 'date': '', 'complete': True,
         'body': 'Check-in is at 3 p.m. Breakfast is at 7 a.m. Wi-Fi password: MapleGuest42! '
                 'Parking is free. Pets require registration.'},
    ]})
    result = local_model.answer('What is the Wi-Fi password for my hotel?', context)
    assert result.get('ok')
    text = result['data']['text']
    assert 'MapleGuest42!' in text
    assert 'reply' not in text.lower()


def test_explicit_reply_request_in_excerpt_is_not_lost(local_model):
    context = json.dumps({'kind': 'email_review', 'scope': 'Checked 1 unread message.', 'messages': [
        {'sender': 'Taylor Nguyen', 'subject': 'Interview slots', 'date': '', 'complete': False,
         'body': 'Could you reply by Friday with your availability for a Tuesday interview? '
                 + 'Our recruiting team is attending the career fair. ' * 15},
    ]})
    result = local_model.answer('Check my unread emails and tell me which need a reply', context)
    assert result.get('ok')
    text = result['data']['text']
    assert 'Reply requested in excerpt' in text
    assert 'Friday' in text
    assert 'Rest not reviewed' in text


def test_rendering_keeps_other_emails_after_failure_and_handles_empty_fields(tmp_path):
    source = (Path(__file__).resolve().parents[1] / 'native/AgentGateModel.swift').read_text()
    assert '@main\nstruct AgentGateModel' in source
    source = source.replace('@main\nstruct AgentGateModel', 'struct AgentGateModel', 1)
    source += '''
@main struct RenderCheck {
    static func main() async {
        if #available(macOS 26.0, *) {
            let messages = ["Failed sender", "Empty sender", "Working sender"].map {
                EmailInput(sender: $0, subject: "Source subject", date: "", body: "Message text", complete: true)
            }
            let review = EmailReview(kind: "email_review", scope: "Checked 3 unread messages.", messages: messages)
            let text = await AgentGateModel.emailReply(review, prompt: "Review these emails") { email, prompt in
                if email.sender == "Failed sender" { throw NSError(domain: "sample-only", code: 1) }
                if email.sender == "Empty sender" {
                    return EmailAssessment(summary: "", replyNeed: .needed, reason: "")
                }
                return EmailAssessment(summary: "An event announcement.",
                                       replyNeed: .notNeeded, reason: String(repeating: "An informational message ", count: 20))
            }
            print(text)
        }
    }
}
'''
    check = tmp_path / 'render.swift'
    check.write_text(source)
    binary = tmp_path / 'render'
    subprocess.run([shutil.which('swiftc'), '-parse-as-library', str(check), '-o', str(binary),
                    '-framework', 'Foundation', '-framework', 'FoundationModels'],
                   check=True, capture_output=True, timeout=120)
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=10)
    assert 'Failed sender: Source subject' in result.stdout
    assert "couldn't summarize this email" in result.stdout
    assert 'Empty sender: Source subject' in result.stdout
    assert 'Reply need unclear: The model did not provide a supporting reason.' in result.stdout
    assert 'Working sender: An event announcement.' in result.stdout
    assert 'The message appears informational, without a personal response request.' in result.stdout
    assert '…' not in result.stdout
