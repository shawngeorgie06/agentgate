"""Authorization must be rechecked after provider waits, before side effects."""
from types import SimpleNamespace

import pytest

from broker.integrations.gmail import Gmail
from tests.test_gmail import make_tools, raw_message


def test_revocation_during_token_refresh_blocks_post(tmp_path, monkeypatch):
    from broker.integrations import gmail as module
    broker, _, _, _ = make_tools(tmp_path)
    provider = Gmail(broker.store)
    provider._credentials = SimpleNamespace(token='test-only', valid=True)
    provider._service = object()
    active = True
    checked = []
    def guard():
        checked.append(active)
        if not active:
            raise RuntimeError('Access revoked')
    def refresh():
        nonlocal active
        active = False
    provider._refresh = refresh
    posts = []
    monkeypatch.setattr(module.requests, 'post', lambda *args, **kwargs: posts.append(args))
    with pytest.raises(RuntimeError, match='Access revoked'):
        provider.call('send', snapshot={'raw':raw_message()}, before_dispatch=guard)
    assert checked == [True, False]
    assert posts == []


def test_revocation_during_provider_initialization_blocks_draft(tmp_path):
    broker, service, provider, _ = make_tools(tmp_path)
    active = True
    original = provider._get_service
    def get_service():
        nonlocal active
        active = False
        return original()
    provider._get_service = get_service
    def guard():
        if not active:
            raise RuntimeError('Access revoked')
    with pytest.raises(RuntimeError, match='Access revoked'):
        provider.call('draft', to='recipient@example.test', subject='Subject', body='Body', before_dispatch=guard)
    assert not any(call[1] == 'create' for call in service.calls)
