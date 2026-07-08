from __future__ import annotations

import pytest

from broker.aws_resource_store import AwsResource, AwsResourceStore


def _res(name="s3-reader", external_id=None):
    return AwsResource(
        name=name, role_arn="arn:aws:iam::123456789012:role/agent-s3-reader",
        region="us-east-1", external_id=external_id,
        created_at="2026-07-06T10:00:00+00:00",
    )


def test_store_get_roundtrip(tmp_path):
    store = AwsResourceStore(str(tmp_path / "r.json"), "pw")
    store.store(_res(external_id="ext-1"))
    assert store.get("s3-reader") == _res(external_id="ext-1")


def test_get_unknown_raises_keyerror(tmp_path):
    with pytest.raises(KeyError):
        AwsResourceStore(str(tmp_path / "r.json"), "pw").get("nope")


def test_delete_and_list_names(tmp_path):
    store = AwsResourceStore(str(tmp_path / "r.json"), "pw")
    store.store(_res("b"))
    store.store(_res("a"))
    assert store.list_names() == ["a", "b"]
    store.delete("a")
    assert store.list_names() == ["b"]
    with pytest.raises(KeyError):
        store.delete("a")


def test_list_metadata_is_full_record(tmp_path):
    store = AwsResourceStore(str(tmp_path / "r.json"), "pw")
    store.store(_res(external_id="ext-1"))
    (meta,) = store.list_metadata()
    assert meta == {
        "name": "s3-reader",
        "role_arn": "arn:aws:iam::123456789012:role/agent-s3-reader",
        "region": "us-east-1", "external_id": "ext-1",
        "created_at": "2026-07-06T10:00:00+00:00",
    }
