#!/usr/bin/env python3

import subprocess as sp
from glob import glob
from pathlib import Path

from loguru import logger

from .docker_runner import DockerRunner
from .misc import SYSTEM_CFG, cfg_setter, get_sha256_from_file, get_value_from_section_by_key, new_context, tmux, tmux_shell

GDB_SCRIPT_HIST = Path(".gdb_hist")


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DEBUGGER                                                                                            |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class Debugger(DockerRunner):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        user_cfg = kwargs.get("user_cfg", "")
        cfg_setter(self, ["general", "debugger"], user_cfg, exclude_keys=["kernel_root"])
        if kwargs.get("ctf_ctx", False):
            self.ctf = True
            self._set_ctf_ctx(kwargs)
        else:
            self.ctf = False
            self.project_dir = Path.cwd() / self.kernel_root
        self.custom_gdb_script = Path("/home/") / self.user / Path(self.gdb_script).name
        self.script_logging = "set -e" if kwargs.get("log_level", "INFO") == "INFO" else "set -eux"
        self.skip_prompts = kwargs.get("skip_prompts", False)
        self.debuggee_name = get_value_from_section_by_key(SYSTEM_CFG, "debuggee_docker", "tag")

    def _set_ctf_ctx(self, kwargs) -> None:
        self.ctf_kernel = Path(kwargs.get("ctf_kernel", ""))
        self.project_dir = Path(self.ctf_dir).resolve().absolute()
        vmlinux = Path(self.project_dir) / "vmlinux"
        if not vmlinux.exists() or b"ELF" not in sp.run(f"file {vmlinux}", shell=True, capture_output=True).stdout:
            if self._extract_vmlinux():
                exit(-1)

    def _extract_vmlinux(self) -> int:
        vml_ext = Path(glob("**/extract-vmlinux.sh", recursive=True)[0]).resolve().absolute()
        pkernel = self.ctf_kernel.resolve().absolute()
        with new_context(self.ctf_dir):
            cmd = f"{vml_ext} {pkernel}"
            ret = sp.run(f"{cmd}", shell=True, capture_output=True)
            if ret.returncode == 0:
                logger.info("Successfully extracted 'vmlinux' from compressed kernel")
                return 0
            else:
                logger.error("Failed to extract 'vmlinux'")
                return 1

    def run_container(self) -> None:
        entrypoint = f'/bin/bash -c "{self.script_logging}; . /home/{self.user}/debugger.sh -a {self.arch} -p {self.docker_mnt} -c {int(self.ctf)} -g {self.custom_gdb_script} -e {self.ext}"'
        runner = f'docker run --pid=container:{self.debuggee_name} -it --rm --security-opt seccomp=unconfined --cap-add=SYS_PTRACE -v {self.project_dir}:/io --net="host" {self.tag} {entrypoint}'
        tmux("selectp -t 2")
        tmux_shell(runner)

    @staticmethod
    def _is_gdb_script_hist() -> bool:
        return GDB_SCRIPT_HIST.exists()

    def _handle_gdb_change(self) -> None:
        src = get_sha256_from_file(Path(self.gdb_script))
        if self._is_gdb_script_hist():
            dst = GDB_SCRIPT_HIST.read_text()
            if dst != src:
                logger.debug(f"Detected changes in {self.gdb_script}. Rebuilding debugger!")
                self.force_rebuild = True
                GDB_SCRIPT_HIST.write_text(src)
        else:
            GDB_SCRIPT_HIST.write_text(src)

    def run(self) -> None:
        self._handle_gdb_change()
        super().run(check_existing=True)
