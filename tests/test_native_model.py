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
    subprocess.run(['/usr/bin/swiftc', '-parse-as-library', str(source), '-o', str(helper),
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
    assert "can't determine whether a reply is needed" in text
    assert 'No reply' not in text and 'lol' not in text
