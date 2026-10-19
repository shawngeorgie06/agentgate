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


@pytest.mark.parametrize('body,limitation', [('', 'Body unavailable'), ('An announcement...', 'Only excerpts reviewed')])
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
        assert "Reply requested" not in text
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
    assert 'Only excerpts reviewed' in text


def test_rendering_keeps_other_emails_after_failure_and_handles_empty_fields(tmp_path):
    source = (Path(__file__).resolve().parents[1] / 'native/AgentGateModel.swift').read_text()
    assert '@main\nstruct AgentGateModel' in source
    source = source.replace('@main\nstruct AgentGateModel', 'struct AgentGateModel', 1)
    source += '''
@main struct RenderCheck {
    static func main() async {
        if #available(macOS 26.0, *) {
            let requests: [(String, Bool)] = [
                ("anything worth replying to?", true),
                ("who should I be responding to", true),
                ("do I need to answer anyone?", true),
                ("any emails I have to deal with?", true),
                ("which messages should I act on?", true),
                ("tell me which emails need a reply", true),
                ("did anyone ask me to reply?", true),
                ("Did any of them need a reply?", true),
                ("has anyone asked me to respond?", true),
                ("Did HSBC ask for a response?", true),
                ("  Did anyone want a reply", true),
                ("what did delta say in their response?", true),
                ("did hsbc reply about my card?", true),
                ("when do I get back from Denver?", false),
                ("what time does my return flight get back?", false),
                ("what is the hotel Wi-Fi password?", false),
                ("what gate and seat am I in?", false),
            ]
            for (question, expected) in requests {
                assert(AgentGateModel.wantsReplyAssessment(question) == expected, question)
            }
            let longDeadline = "The sender asks for availability by Fri. Dec. 6 " + String(repeating: "for a phone screen ", count: 10)
            assert(AgentGateModel.explanation(longDeadline, limit: 90, need: .reply)
                   == "The message appears to request a personal response.")
            let messages = ["Failed sender", "Empty sender", "Working sender"].map {
                EmailInput(sender: $0, subject: "Source subject", date: "", body: "Message text", complete: true)
            }
            let review = EmailReview(kind: "email_review", scope: "Checked 3 unread messages.", messages: messages)
            let text = await AgentGateModel.emailReply(review, prompt: "Review these emails") { email, prompt in
                if email.sender == "Failed sender" { throw NSError(domain: "sample-only", code: 1) }
                if email.sender == "Empty sender" {
                    return EmailAssessment(summary: "", followUp: .reply, reason: "")
                }
                return EmailAssessment(summary: "An event announcement.",
                                       followUp: .none, reason: String(repeating: "An informational message ", count: 20))
            }
            print(text)
            let wideMessages = (0..<3).map { _ in
                EmailInput(sender: String(repeating: "S", count: 200), subject: String(repeating: "T", count: 200),
                           date: "", body: "Message text", complete: true)
            }
            let wideReview = EmailReview(kind: "email_review",
                scope: "Checked 3 matching messages from the first search page, not the entire inbox.", messages: wideMessages)
            let wideText = await AgentGateModel.emailReply(wideReview, prompt: "Which need a reply?") { _, _ in
                EmailAssessment(summary: String(repeating: "U", count: 150), followUp: .none,
                                reason: String(repeating: "V", count: 90))
            }
            assert(wideText.unicodeScalars.count <= 1200, "Three-email review exceeded the output budget")
            assert(wideText.components(separatedBy: "No follow-up appears needed").count == 4)
            let notifications = (0..<3).map { _ in
                EmailInput(sender: "CodeRabbit", subject: "Review of PR #14", date: "",
                           body: "Fix review comments", complete: false, source: "github")
            }
            let notificationText = await AgentGateModel.emailReply(
                EmailReview(kind: "email_review", scope: wideReview.scope, messages: notifications),
                prompt: "Which need a reply?") { _, _ in
                    EmailAssessment(summary: "Fix review comments on PR #14.", followUp: .reply,
                                    reason: "The sender requests a personal response.", requestQuote: "Fix review comments")
                }
            assert(notificationText.components(separatedBy: "Task mentioned in excerpt").count == 4)
            assert(!notificationText.contains("personal response"))
            assert(!notificationText.contains("Reply needed"))
            assert(notificationText.components(separatedBy: "Only excerpts reviewed").count == 2)
            assert(notificationText.unicodeScalars.count <= 1200)
            let partialWide = wideMessages.map { email in
                EmailInput(sender: email.sender, subject: email.subject, date: "", body: email.body, complete: false)
            }
            let partialText = await AgentGateModel.emailReply(
                EmailReview(kind: "email_review", scope: wideReview.scope, messages: partialWide),
                prompt: "Which need a reply?") { _, _ in
                    EmailAssessment(summary: String(repeating: "U", count: 150), followUp: .task,
                                    reason: String(repeating: "V", count: 90), requestQuote: "Message text")
                }
            assert(partialText.unicodeScalars.count <= 1200, "Partial review exceeded output budget")

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
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr[:1200]
    assert 'Failed sender: Source subject' in result.stdout
    assert "couldn't summarize this email" in result.stdout
    assert 'Empty sender: Source subject' in result.stdout
    assert 'Follow-up unclear: No matching request was found in the supplied body.' in result.stdout
    assert 'Working sender: An event announcement.' in result.stdout
    assert 'The message appears informational, without a personal response request.' in result.stdout
    assert '…' not in result.stdout


def test_github_notification_reports_task_and_preserves_targeted_metadata(local_model):
    context = json.dumps({'kind': 'email_review', 'scope': 'Checked 1 requested email.', 'messages': [
        {'sender': 'coderabbitai[bot]', 'source': 'github', 'subject': 'Review of PR #14',
         'date': '', 'complete': False,
         'body': 'Fix CodeRabbit comments on PR #14: separate HTML table cells. '
                 'Review profile: CHILL. Plan: Advanced. Run ID: synthetic-run-42. '},
    ]})
    result = local_model.answer('Which emails need a reply?', context)
    assert result.get('ok')
    text = result['data']['text']
    assert 'Task mentioned' in text
    assert 'Reply needed' not in text and 'Reply requested' not in text
    assert 'CHILL' not in text and 'Run ID' not in text and 'Advanced' not in text
    assert '14' in text and 'table' in text.lower()
    detail = local_model.answer('What run ID does the review notification give?', context)
    assert detail.get('ok')
    assert 'synthetic-run-42' in detail['data']['text']
