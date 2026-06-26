from likedbg.debug_profiles import (
    Expect,
    ResolvedDebugProfiles,
    parse_kernel_release,
    verify_config,
    version_tuple,
)


def _resolved(*exp: Expect) -> ResolvedDebugProfiles:
    return ResolvedDebugProfiles(names=("kasan",), base="exploit-dev", expected_config=exp, future_breakpoint_groups=())


def test_hard_pass_and_not_set_parsing() -> None:
    cfg = "CONFIG_KASAN=y\n# CONFIG_RANDOMIZE_BASE is not set\n"
    res = _resolved(
        Expect(symbol="CONFIG_KASAN", value="y", severity="hard"),
        Expect(symbol="CONFIG_RANDOMIZE_BASE", value="n", severity="hard"),
    )
    v = verify_config(cfg, res, target_arch="x86_64", kernel_release="6.6.30")
    assert not v.missing_hard and len(v.satisfied) == 2


def test_hard_fail() -> None:
    res = _resolved(Expect(symbol="CONFIG_KASAN", value="y", severity="hard"))
    v = verify_config("# CONFIG_KASAN is not set\n", res, target_arch="x86_64", kernel_release="6.6.30")
    assert [e.symbol for e in v.missing_hard] == ["CONFIG_KASAN"]


def test_soft_warns_not_fails() -> None:
    res = _resolved(Expect(symbol="CONFIG_FRAME_POINTER", value="y", severity="soft"))
    v = verify_config("", res, target_arch="x86_64", kernel_release="6.6.30")
    assert not v.missing_hard and [e.symbol for e in v.missing_soft] == ["CONFIG_FRAME_POINTER"]


def test_arch_selector_skips() -> None:
    res = _resolved(Expect(symbol="CONFIG_X", value="y", severity="hard", arch=("arm64",)))
    v = verify_config("", res, target_arch="x86_64", kernel_release="6.6.30")
    assert not v.missing_hard and not v.satisfied  # skipped entirely


def test_kernel_min_skips_on_older() -> None:
    res = _resolved(Expect(symbol="CONFIG_X", value="y", severity="hard", kernel_min="6.7"))
    v = verify_config("", res, target_arch="x86_64", kernel_release="6.6.30")
    assert not v.missing_hard


def test_parse_kernel_release() -> None:
    mk = "VERSION = 6\nPATCHLEVEL = 6\nSUBLEVEL = 30\nEXTRAVERSION =\nNAME = x\n"
    assert parse_kernel_release(mk) == "6.6.30"
    assert version_tuple("6.6.30") == (6, 6, 30)
