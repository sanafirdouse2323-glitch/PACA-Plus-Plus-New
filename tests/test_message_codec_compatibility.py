from __future__ import annotations

import pytest

import paca
from paca.memory import HMACAgentMessageCodec


def test_package_and_legacy_memory_imports_share_the_public_codec() -> None:
    assert paca.HMACAgentMessageCodec is HMACAgentMessageCodec
    assert HMACAgentMessageCodec.__module__ == "paca.memory"


def test_message_codec_rejects_short_hmac_keys_before_binding_dependencies() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        HMACAgentMessageCodec(b"x" * 31, None, None, memory=None)


def test_message_codec_rejects_unbound_memory_and_authority() -> None:
    with pytest.raises(ValueError, match="share the same trusted state"):
        HMACAgentMessageCodec(b"x" * 32, object(), object(), memory=None)


def test_dedicated_message_module_preserves_legacy_and_pickle_imports() -> None:
    import pickle

    from paca.messages import HMACAgentMessageCodec as dedicated_codec

    assert dedicated_codec is HMACAgentMessageCodec
    assert dedicated_codec is paca.HMACAgentMessageCodec
    assert dedicated_codec.__module__ == "paca.memory"
    assert pickle.loads(pickle.dumps(dedicated_codec)) is dedicated_codec
