import pytest
from pydantic import ValidationError

from likedbg.config import BuildCfg
from likedbg.config import CacheCfg
from likedbg.config import DebuggeeCfg
from likedbg.config import DebuggerCfg
from likedbg.config import ExploitCfg
from likedbg.config import ForeignCfg
from likedbg.config import GeneralCfg
from likedbg.config import Settings
from likedbg.config import SourceCfg
from likedbg.errors import ConfigError


def test_defaults_match_grill_decisions() -> None:
    s = Settings()
    assert s.general.arch == "native"
    assert s.source.kind == "version"
    assert s.debugger.ext == "pwndbg"  # de facto default (Q9)
    assert s.general.profiles == ("exploit-dev",)


def test_list_fields_are_tuples() -> None:
    b = BuildCfg(patch_dirs=["patches/uaf"], extra_fragments=["configs/fragments/local/x.config"])
    assert b.patch_dirs == ("patches/uaf",)
    assert b.extra_fragments == ("configs/fragments/local/x.config",)
    assert GeneralCfg(profiles=["kasan", "lockdep"]).profiles == ("kasan", "lockdep")
    assert ExploitCfg(flags=["-lpthread"]).flags == ("-lpthread",)


def test_unknown_key_is_rejected() -> None:
    with pytest.raises(ValidationError):
        GeneralCfg(arch="native", bogus=1)  # type: ignore[call-arg]


def test_source_kind_constrained() -> None:
    with pytest.raises(ValidationError):
        SourceCfg(kind="branch", value="x")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# FIX 2: path-traversal validation for BuildCfg
# ---------------------------------------------------------------------------


def test_build_cfg_rejects_absolute_patch_dir() -> None:
    """Absolute path in patch_dirs must raise ConfigError."""
    with pytest.raises(ConfigError, match="absolute"):
        BuildCfg(patch_dirs=["/etc/passwd"])


def test_build_cfg_rejects_dotdot_patch_dir() -> None:
    """'..' traversal in patch_dirs must raise ConfigError."""
    with pytest.raises(ConfigError, match=r"\.\.|traversal"):
        BuildCfg(patch_dirs=["../evil"])


def test_build_cfg_rejects_absolute_custom_module() -> None:
    """Absolute path in custom_modules must raise ConfigError."""
    with pytest.raises(ConfigError, match="absolute"):
        BuildCfg(custom_modules=["/tmp/module"])


def test_build_cfg_rejects_dotdot_custom_module() -> None:
    """'..' traversal in custom_modules must raise ConfigError."""
    with pytest.raises(ConfigError, match=r"\.\.|traversal"):
        BuildCfg(custom_modules=["modules/../../../evil"])


def test_build_cfg_rejects_absolute_extra_fragment() -> None:
    """Absolute path in extra_fragments must raise ConfigError."""
    with pytest.raises(ConfigError, match="absolute"):
        BuildCfg(extra_fragments=["/configs/fragments/x.config"])


def test_build_cfg_rejects_dotdot_extra_fragment() -> None:
    """'..' traversal in extra_fragments must raise ConfigError."""
    with pytest.raises(ConfigError, match=r"\.\.|traversal"):
        BuildCfg(extra_fragments=["configs/fragments/../../evil.config"])


def test_build_cfg_rejects_extra_fragment_outside_fragments_dir() -> None:
    """extra_fragments outside 'configs/fragments/' must raise ConfigError."""
    with pytest.raises(ConfigError, match="configs/fragments/"):
        BuildCfg(extra_fragments=["configs/my-local.config"])


def test_build_cfg_accepts_valid_paths() -> None:
    """Valid relative paths must be accepted without error."""
    b = BuildCfg(
        patch_dirs=["patches/uaf", "patches/heap"],
        custom_modules=["modules/my-exploit-mod"],
        extra_fragments=["configs/fragments/local/hardened.config"],
    )
    assert b.patch_dirs == ("patches/uaf", "patches/heap")
    assert b.custom_modules == ("modules/my-exploit-mod",)
    assert b.extra_fragments == ("configs/fragments/local/hardened.config",)


# ---------------------------------------------------------------------------
# Crash config defaults (Task 7)
# ---------------------------------------------------------------------------


def test_crash_config_defaults() -> None:
    assert DebuggeeCfg().capture_console is True
    dg = DebuggerCfg()
    assert dg.break_on_crash is True
    assert dg.crash_breakpoints == ("panic", "die", "oops_enter")
    assert dg.sanitizer_breakpoints == ()


def test_crash_breakpoints_overridable() -> None:
    dg = DebuggerCfg(crash_breakpoints=["panic", "die"])
    assert dg.crash_breakpoints == ("panic", "die")


def test_debuginfod_config_defaults() -> None:
    dg = DebuggerCfg()
    assert dg.debuginfod == "auto"
    assert dg.debuginfod_urls == "https://debuginfod.elfutils.org"


def test_debuginfod_mode_constrained() -> None:
    with pytest.raises(ValidationError):
        DebuggerCfg(debuginfod="sometimes")  # type: ignore[arg-type]


def test_debuginfod_overridable() -> None:
    dg = DebuggerCfg(debuginfod="on", debuginfod_urls="https://mirror.example/dbginfo")
    assert dg.debuginfod == "on"
    assert dg.debuginfod_urls == "https://mirror.example/dbginfo"


def test_guest_loop_config_defaults() -> None:
    d = DebuggeeCfg()
    assert d.ssh_port == 2222
    assert d.share_dir == "exploit"
    assert d.guest_net is True
    assert d.share is True


# ---------------------------------------------------------------------------
# ForeignCfg (Task 1)
# ---------------------------------------------------------------------------


def test_foreign_cfg_defaults_empty_and_presence_selects() -> None:
    f = ForeignCfg()
    assert f.image == "" and f.vmlinux == "" and f.initramfs == ""
    assert f.cmdline == "" and f.arch == "" and f.exploit == ""
    assert f.qemu_extra == ()
    # presence of image is the selector the CLI keys on
    assert ForeignCfg(image="ctf/lk01/bzImage").image == "ctf/lk01/bzImage"


def test_foreign_cfg_accepts_absolute_paths() -> None:
    """Foreign inputs are read-only external artifacts: absolute paths ARE allowed."""
    f = ForeignCfg(
        image="/home/ctf/lk01/bzImage",
        vmlinux="/home/ctf/lk01/vmlinux",
        initramfs="/home/ctf/lk01/initramfs.cpio.gz",
        exploit="/home/ctf/lk01/exploit.c",
    )
    assert f.image == "/home/ctf/lk01/bzImage"
    assert f.vmlinux == "/home/ctf/lk01/vmlinux"


def test_foreign_cfg_rejects_dotdot_traversal() -> None:
    with pytest.raises(ConfigError, match=r"\.\.|traversal"):
        ForeignCfg(image="../../etc/passwd")


def test_foreign_cfg_qemu_extra_is_tuple() -> None:
    f = ForeignCfg(qemu_extra=["-cpu", "qemu64,+smep"])
    assert f.qemu_extra == ("-cpu", "qemu64,+smep")


def test_foreign_cfg_rejects_unknown_key() -> None:
    with pytest.raises(ValidationError):
        ForeignCfg(bogus=1)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# ccache config (Task 1)
# ---------------------------------------------------------------------------


def test_ccache_config_defaults() -> None:
    b = BuildCfg()
    assert b.ccache is True
    assert b.ccache_max_size == "5G"


def test_ccache_overridable() -> None:
    b = BuildCfg(ccache=False, ccache_max_size="10G")
    assert b.ccache is False and b.ccache_max_size == "10G"


# ---------------------------------------------------------------------------
# CacheCfg (Task 1)
# ---------------------------------------------------------------------------


def test_cache_cfg_defaults() -> None:
    c = CacheCfg()
    assert c.max_size == ""


def test_cache_cfg_overridable() -> None:
    c = CacheCfg(max_size="20G")
    assert c.max_size == "20G"


def test_cache_cfg_rejects_unknown_key() -> None:
    with pytest.raises(ValidationError):
        CacheCfg(bogus=1)  # type: ignore[call-arg]


def test_settings_has_cache_config() -> None:
    s = Settings()
    assert s.cache.max_size == ""
    assert isinstance(s.cache, CacheCfg)


def test_foreign_cfg_net_defaults():
    from likedbg.config import ForeignCfg

    fc = ForeignCfg()
    assert fc.net is True
    assert fc.net_iface == "eth0"

    fc2 = ForeignCfg(net=False, net_iface="enp0s3")
    assert fc2.net is False and fc2.net_iface == "enp0s3"
