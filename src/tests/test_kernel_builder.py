import collections
import configparser
import uuid
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import docker
import pytest

try:
    from src.kernel_builder import MISC_DRVS_PATH, KernelBuilder  # legacy; may not install in new env

    _LEGACY_AVAILABLE = True
except ImportError:
    _LEGACY_AVAILABLE = False
    KernelBuilder = None  # type: ignore[assignment,misc]
    MISC_DRVS_PATH = None  # type: ignore[assignment]

USER_INI = Path("configs/user.ini")
CUSTOM_MODULE = Path("examples/like_dbg_confs/echo_module_x86.ini")


def fetch_cfg_value_from_section_and_key(c: Path, sect: str, key: str) -> str:
    cfg = configparser.ConfigParser()
    cfg.read(c)
    return cfg[sect][key]


def are_lists_equal(x, y) -> bool:
    return collections.Counter(x) == collections.Counter(y)


@patch("os.getuid", return_value=1)
def test_make_sudo_user(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    assert kb.make_sudo("test") == "test"


@patch("os.getuid", return_value=0)
def test_make_sudo_root(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    assert kb.make_sudo("test") == "sudo test"


def test_custom_args() -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.enable_args = "FOO BAR"
    kb.disable_args = " BAZ QUX"
    assert kb._custom_args() == "-e FOO -e BAR -d BAZ -d QUX"


def test_extra_args() -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.extra_args = "-e FOO -d BAR"
    expected = "-e FOO -d BAR".split()
    actual = kb._extra_args("-e BAR").split()
    assert are_lists_equal(expected, actual) is True


@patch.object(KernelBuilder, "_run_ssh", return_value=0)
def test_get_params_syzkaller(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = "syzkaller"
    assert kb._get_params() == fetch_cfg_value_from_section_and_key(USER_INI, "kernel_builder", "syzkaller_args")


@patch.object(KernelBuilder, "_run_ssh", return_value=0)
def test_build_arch_llvm_params(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.arch = "x86_64"
    kb.cc = "CC=clang"
    kb.llvm_flag = "LLVM=1"
    kb.mode = "generic"
    assert "-e LTO_NONE -d LTO_CLANG_FULL -d LTO_CLANG_THIN " in kb._get_params()


@patch.object(KernelBuilder, "_run_ssh", return_value=0)
def test_build_arch_not_llvm_params(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.arch = "x86_64"
    kb.mode = "generic"
    assert "-e LTO_NONE -d LTO_CLANG_FULL -d LTO_CLANG_THIN " not in kb._get_params()


@patch.object(KernelBuilder, "_run_ssh", return_value=0)
def test_get_params_generic(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = "generic"
    assert kb._get_params() == fetch_cfg_value_from_section_and_key(USER_INI, "kernel_builder", "generic_args")


@patch.object(KernelBuilder, "_run_ssh", return_value=0)
def test_get_params_custom(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = "custom"
    kb.enable_args = "FOO BAR"
    kb.disable_args = " BAZ QUX"
    assert kb._get_params() == "-e FOO -e BAR -d BAZ -d QUX"


@patch.object(KernelBuilder, "_run_ssh", return_value=0)
def test_get_params_extra(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = ""
    kb.extra_args = "-e FOO -d BAR"
    assert kb._get_params() == kb.extra_args


@patch.object(KernelBuilder, "_run_ssh", return_value=0)
def test_get_params_extra_override(self) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = "generic"
    kb.extra_args = "-d DEBUG_KERNEL"
    assert kb._get_params() == fetch_cfg_value_from_section_and_key(USER_INI, "kernel_builder", "generic_args").replace(
        "-e DEBUG_KERNEL", kb.extra_args
    )


def test_add_modules() -> None:
    p = Path(f"/tmp/{uuid.uuid1().hex}")
    kb = KernelBuilder(**{"kroot": p})
    kb.custom_modules = fetch_cfg_value_from_section_and_key(CUSTOM_MODULE, "kernel_builder", "custom_modules")
    Path(p / MISC_DRVS_PATH).mkdir(parents=True)
    fst = "This is the 1st line."
    lst = "This is the last line."
    q = Path(p / MISC_DRVS_PATH / "Makefile")
    q.touch()
    q.write_text(fst)
    r = Path(p / MISC_DRVS_PATH / "Kconfig")
    r.touch()
    r.write_text(f"{fst}\n{lst}")
    kb._add_modules()
    data = Path(q).read_text().splitlines()
    assert data[-1] != fst
    data = Path(r).read_text().splitlines()
    assert data[-1] == lst
    assert data[-2] != fst


def test_add_module() -> None:
    p = Path(f"/tmp/{uuid.uuid1().hex}")
    kb = KernelBuilder(**{"kroot": p})
    kb.custom_modules = fetch_cfg_value_from_section_and_key(CUSTOM_MODULE, "kernel_builder", "custom_modules")
    kb.custom_modules += "echo_service"
    Path(p / MISC_DRVS_PATH).mkdir(parents=True)
    fst = "This is the 1st line."
    lst = "This is the last line."
    q = Path(p / MISC_DRVS_PATH / "Makefile")
    q.touch()
    q.write_text(fst)
    r = Path(p / MISC_DRVS_PATH / "Kconfig")
    r.touch()
    r.write_text(f"{fst}\n{lst}")
    kb._add_modules()
    data = Path(q).read_text().splitlines()
    assert data[-1] != fst
    data = Path(r).read_text().splitlines()
    assert data[-1] == lst
    assert data[-2] != fst


@patch.object(KernelBuilder, "_run_ssh")
def test_build_arch_no_args(mock_m) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb._build_arch()
    mock_m.assert_called_with("CC=gcc  make x86_64_defconfig")


@patch.object(KernelBuilder, "_run_ssh")
def test_build_arch_llvm(mock_m) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.arch = "x86_64"
    kb.cc = "CC=clang"
    kb.llvm_flag = "LLVM=1"
    kb._build_arch()
    mock_m.assert_called_with("CC=clang LLVM=1 make x86_64_defconfig")


@patch.object(KernelBuilder, "_run_ssh")
def test_build_arch_arm(mock_m) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.arch = "aarch64"
    kb._build_arch()
    mock_m.assert_called_with(f"CC=gcc  ARCH={kb.arch} make defconfig")


@patch.object(KernelBuilder, "_run_ssh")
def test_build_kvm_guest(mock_m) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb._build_kvm_guest()
    mock_m.assert_called_with(f"CC=gcc  ARCH={kb.arch} make kvm_guest.config")


@patch.object(KernelBuilder, "_run_ssh")
def test_configure_kernel(mock_m) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.mode = ""
    kb.extra_args = "-e FOO -d BAR"
    kb._configure_kernel()
    mock_m.assert_called_with(f"./scripts/config {kb.extra_args}")


@patch.object(KernelBuilder, "_run_ssh")
def test_build_mrproper(mock_m) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb._build_mrproper()
    mock_m.assert_called_with("CC=gcc ARCH=x86_64 make mrproper")


@patch.object(KernelBuilder, "_run_ssh")
def test_make_clean(mock_m) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb._make_clean()
    mock_m.assert_called_with("make clean")


@patch.object(KernelBuilder, "_run_ssh", return_value=0)
def test_make_sucess(mock_m) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb._make()
    mock_m.assert_called_with("CC=gcc ARCH=x86_64  make -j$(nproc) modules")


def throw_with_cause():
    raise Exception("Failed") from ValueError("That was unexpected.")


def test_general_exception() -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    with pytest.raises(SystemExit) as ext:
        kb.run_container()
    assert ext.type == SystemExit
    assert ext.value.code == -2


@patch.object(KernelBuilder, "_run_ssh", return_value=1)
@patch.object(KernelBuilder, "stop_container", return_value=0)
def test_make_fail(mock_m, mock_k) -> None:
    with pytest.raises(SystemExit) as ext:
        kb = KernelBuilder(**{"kroot": "foo"})
        kb._make()
    assert ext.type == SystemExit
    assert ext.value.code == -1


@patch.object(KernelBuilder, "_run_ssh", return_value=0)
def test_apply_patches(mock_m, tmp_path) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.patch_dir = tmp_path
    Path(tmp_path / "patch_a").touch()
    Path(tmp_path / "patch_b").touch()
    assert kb._apply_patches() == 0


@patch.object(KernelBuilder, "_run_ssh", return_value=1)
def test_apply_patches_fail(mock_m, tmp_path) -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.patch_dir = tmp_path
    Path(tmp_path / "patch_a").touch()
    assert kb._apply_patches() == 1


def test_run_ssh_success() -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.ssh_conn = MagicMock()
    cmd = "foobar --baz"
    expected = f"cd {kb.docker_mnt}/{kb.kernel_root} && {cmd}"
    kb._run_ssh(cmd)
    kb.ssh_conn.run.assert_called_with(expected, echo=True, warn=False)


def get_run_kbuilder(mode: str) -> KernelBuilder:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.custom_modules = True
    kb.ssh_fwd_port = 2222
    kb.client = docker.DockerClient()
    kb.ssh_conn = Mock()
    kb.mode = mode
    kb.kvm = True
    kb.image = "busybox"
    kb.dirty = True
    return kb


@patch.object(KernelBuilder, "_add_modules", return_value=0)
@patch.object(KernelBuilder, "_make_clean", return_value=0)
@patch.object(KernelBuilder, "_build_mrproper", return_value=0)
@patch.object(KernelBuilder, "_apply_patches", return_value=0)
@patch.object(KernelBuilder, "_build_arch", return_value=0)
@patch.object(KernelBuilder, "_build_kvm_guest", return_value=0)
@patch.object(KernelBuilder, "_configure_kernel", return_value=0)
@patch.object(KernelBuilder, "_make", return_value=0)
@patch.object(KernelBuilder, "wait_for_container", return_value=0)
@patch.object(KernelBuilder, "init_ssh", return_value=0)
@patch.object(KernelBuilder, "_run_ssh", return_value=0)
@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "y")
def test_run_no_config_mode(a, b, c, d, e, f, g, h, j, k, lvname, m):
    kb = get_run_kbuilder("noconfig")
    kb.run()
    expected = f"cd {kb.docker_mnt}/{kb.kernel_root}/arch/{kb.arch}/boot && ln -s bzImage Image"
    kb.ssh_conn.run.assert_called_with(expected, echo=True)


@patch.object(KernelBuilder, "_add_modules", return_value=0)
@patch.object(KernelBuilder, "_make_clean", return_value=0)
@patch.object(KernelBuilder, "_build_mrproper", return_value=0)
@patch.object(KernelBuilder, "_apply_patches", return_value=0)
@patch.object(KernelBuilder, "_build_arch", return_value=0)
@patch.object(KernelBuilder, "_build_kvm_guest", return_value=0)
@patch.object(KernelBuilder, "_configure_kernel", return_value=0)
@patch.object(KernelBuilder, "_make", return_value=0)
@patch.object(KernelBuilder, "wait_for_container", return_value=0)
@patch.object(KernelBuilder, "init_ssh", return_value=0)
@patch.object(KernelBuilder, "_run_ssh", return_value=0)
@patch("termios.tcflush", return_value=True)
@patch("builtins.input", lambda *args: "y")
def test_run_config_mode(a, b, c, d, e, f, g, h, j, k, lvname, m):
    kb = get_run_kbuilder("config")
    kb.run()
    expected = f"cd {kb.docker_mnt}/{kb.kernel_root}/arch/{kb.arch}/boot && ln -s bzImage Image"
    kb.ssh_conn.run.assert_called_with(expected, echo=True)


def test_wait_for_container() -> None:
    kb = KernelBuilder(**{"kroot": "foo"})
    kb.container = Mock()
    kb.container.id = 42
    kb.cli = Mock()
    kb.cli.inspect_container.return_value = {"State": {"Health": {"Status": "healthy"}}}
    kb.wait_for_container()


# ---------------------------------------------------------------------------
# Task-9: BuildStage — patch application + config/release capture
# ---------------------------------------------------------------------------
from likedbg.cache import build_recipe as likedbg_build_recipe  # noqa: E402
from likedbg.config import Settings as LibSettings  # noqa: E402
from likedbg.host_profile import HostProfile, Probes  # noqa: E402
from likedbg.pipeline import PipelineContext  # noqa: E402
from likedbg.stages.build import BuildStage  # noqa: E402


class _FakeContainer:
    def __init__(self) -> None:
        self.cmds: list[str] = []

    def run_detached(self, *a, **k):  # noqa: ANN
        return "c1"

    def exec(self, c, cmd, workdir=None):  # noqa: ANN
        self.cmds.append(cmd)

        class _R:  # noqa
            output = (
                "VERSION = 6\nPATCHLEVEL = 6\nSUBLEVEL = 30\nEXTRAVERSION =\n"
                if "Makefile" in cmd
                else ""
            )

        return _R()

    def stop(self, c):  # noqa: ANN
        pass


def _host_profile(tmp_path: Path) -> HostProfile:
    p = Probes(
        system=lambda: "linux",
        machine=lambda: "x86_64",
        kvm_accessible=lambda: False,
        hvf_supported=lambda: False,
        native_qemu_present=lambda _a: True,
        workspace_case_sensitive=lambda _p: True,
    )
    return HostProfile.detect(LibSettings(), tmp_path, p)


def test_patches_applied_in_order(tmp_path: Path) -> None:
    (tmp_path / "configs" / "fragments").mkdir(parents=True)
    frag = "configs/fragments/generic.config"
    (tmp_path / frag).write_text("CONFIG_X=y\n")
    patches = tmp_path / "patches" / "uaf"
    patches.mkdir(parents=True)
    (patches / "0001-a.patch").write_text("p1")
    (patches / "0002-b.patch").write_text("p2")
    r = likedbg_build_recipe(
        LibSettings(),
        version="6.6.30",
        arch="x86_64",
        workspace=tmp_path,
        fragments=[frag],
        patch_dirs=("patches/uaf",),
    )
    fake = _FakeContainer()
    stage = BuildStage(
        fake,
        recipe=r,
        kbuilder_image="img",
        workspace=tmp_path,
        kernel_volume="vol",
        patch_dirs=("patches/uaf",),
    )
    ctx = PipelineContext(settings=LibSettings(), host=_host_profile(tmp_path), build_label=r.label)
    stage.run(ctx)
    patch_cmds = [c for c in fake.cmds if "patch -p1" in c or "git apply" in c]
    assert len(patch_cmds) == 2  # one per patch file, sorted
