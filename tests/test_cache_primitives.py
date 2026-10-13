import pytest

from likedbg.cache import cache_key
from likedbg.cache import format_size
from likedbg.cache import parse_size
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


# ---------------------------------------------------------------------------
# parse_size tests (Task 1)
# ---------------------------------------------------------------------------


def test_parse_size_empty_string():
    assert parse_size("") == 0


def test_parse_size_gigabytes():
    assert parse_size("50G") == 50 * 1024**3


def test_parse_size_megabytes():
    assert parse_size("500M") == 500 * 1024**2


def test_parse_size_kilobytes():
    assert parse_size("1024K") == 1024 * 1024


def test_parse_size_terabytes():
    assert parse_size("2T") == 2 * 1024**4


def test_parse_size_case_insensitive():
    assert parse_size("10g") == 10 * 1024**3
    assert parse_size("10G") == 10 * 1024**3
    assert parse_size("500m") == 500 * 1024**2
    assert parse_size("500M") == 500 * 1024**2


def test_parse_size_no_unit():
    assert parse_size("1024") == 1024


def test_parse_size_whitespace_stripped():
    assert parse_size("  50G  ") == 50 * 1024**3
    assert parse_size("  100M  ") == 100 * 1024**2


def test_parse_size_float_input():
    assert parse_size("1.5G") == int(1.5 * 1024**3)


def test_parse_size_invalid_unit():
    with pytest.raises(ValueError, match="invalid size"):
        parse_size("50X")


def test_parse_size_invalid_number():
    with pytest.raises(ValueError, match="invalid size"):
        parse_size("notanumber")


# ---------------------------------------------------------------------------
# format_size tests: --list used to print raw byte counts against a config that
# speaks "50G", leaving the arithmetic to the reader.
# ---------------------------------------------------------------------------


def test_format_size_uses_the_same_units_the_config_accepts():
    assert format_size(3 * 1024**3) == "3.0G"
    assert format_size(500 * 1024**2) == "500.0M"
    assert format_size(4096) == "4.0K"
    assert format_size(2 * 1024**4) == "2.0T"


def test_format_size_keeps_sub_kilobyte_counts_exact():
    # Rounding a small file to "0.0K" would hide the difference between empty and nearly-empty.
    assert format_size(0) == "0B"
    assert format_size(900) == "900B"
    assert format_size(1023) == "1023B"


def test_format_size_does_not_stop_scaling_at_terabytes():
    # A cache bigger than 1024T is absurd, but it must not fall out of the loop unformatted.
    assert format_size(5 * 1024**5) == "5120.0T"


@pytest.mark.parametrize("n", [1024, 4096, 3 * 1024**3, 50 * 1024**3, 2 * 1024**4])
def test_format_size_round_trips_through_parse_size(n):
    """The two are a pair: what --list prints must be something --prune/[cache] max_size accepts."""
    assert parse_size(format_size(n)) == n
