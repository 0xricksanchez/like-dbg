#!/usr/bin/env python3

import subprocess as sp
from glob import glob
from pathlib import Path

import docker
from loguru import logger

from .docker_runner import DockerRunner
from .misc import cfg_setter, tmux, tmux_shell, new_context, get_sha256_from_file

GDB_SCRIPT_HIST = Path(".gdb_hist")


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DEBUGGER                                                                                            |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class Debugger(DockerRunner):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        cfg_setter(self, ["general", "debugger"], exclude_keys=["kernel_root"])
        ctf_ctx = kwargs.get("ctf_ctx", False)
        if ctf_ctx:
            self.ctf_kernel = Path(kwargs.get("ctf_kernel", ""))
            self.project_dir = Path.cwd() / self.ctf_dir
            vmlinux = Path(self.project_dir) / "vmlinux"
            if not vmlinux.exists() or b"ELF" not in sp.run(f"file {vmlinux}", shell=True, capture_output=True).stdout:
                self._extract_vmlinux()
        else:
            self.project_dir = Path.cwd() / self.kernel_root
        self.ctf = 1 if ctf_ctx else 0
        self.custom_gdb_script = Path("/home/") / self.user / Path(self.gdb_script).name
        self.script_logging = "set -e" if kwargs.get("log_level", "INFO") == "INFO" else "set -eux"
        self.skip_prompts = kwargs.get("skip_prompts", False)
        self.buildargs = {"USER": self.user}
        self.cli = docker.APIClient(base_url=self.docker_sock)

    def _extract_vmlinux(self) -> None:
        with new_context(self.ctf_dir):
            vml_ext = glob("**/extract*", recursive=True)[0]
            ret = sp.run(f"./{vml_ext} {Path(*self.ctf_kernel.parts[1:])} > vmlinux", shell=True, capture_output=True)
            if ret.returncode == 0:
                logger.info("Successfully extracted 'vmlinux' from compressed kernel")
            else:
                logger.error("Failed to extract 'vmlinux'")
                exit(-1)

    def run_container(self) -> None:
        entrypoint = f'/bin/bash -c "{self.script_logging}; . /home/{self.user}/debugger.sh -a {self.arch} -p {self.docker_mnt} -c {self.ctf} -g {self.custom_gdb_script}"'
        runner = f'docker run -it --rm --security-opt seccomp=unconfined --cap-add=SYS_PTRACE -v {self.project_dir}:/io --net="host" {self.tag} {entrypoint}'
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
                logger.info(f"Detected changes in {self.gdb_script}. Rebuilding debugger!")
                self.force_rebuild = True
                GDB_SCRIPT_HIST.write_text(src)
        else:
            GDB_SCRIPT_HIST.write_text(src)

    def run(self) -> None:
        self._handle_gdb_change()
        self.check_existing()
        super().run()
