from likedbg.cache import cache_key
from likedbg.cache import short_hash
from likedbg.cache import slug


def test_cache_key_is_deterministic_and_order_independent():
    a = cache_key({"version": "6.6.30", "arch": "arm64"})
    b = cache_key({"arch": "arm64", "version": "6.6.30"})
    assert a == b
    assert len(a) == 64


def test_cache_key_is_sensitive_to_any_input_change():
    base = cache_key({"version": "6.6.30", "arch": "arm64"})
    assert cache_key({"version": "6.6.31", "arch": "arm64"}) != base
    assert cache_key({"version": "6.6.30", "arch": "x86_64"}) != base


def test_short_hash_is_first_eight():
    key = cache_key({"x": "y"})
    assert short_hash(key) == key[:8]


def test_slug_is_filesystem_safe():
    assert slug("6.6.30") == "6.6.30"
    assert slug("My Tag/v2") == "my-tag-v2"
    assert slug("--weird__") == "weird__"


def test_slug_empty_string():
    assert slug("") == ""


def test_slug_already_clean_roundtrips():
    assert slug("linux-6.6.30") == "linux-6.6.30"
