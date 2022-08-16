#!/usr/bin/env python3

import subprocess as sp
from glob import glob
from pathlib import Path

import docker
from loguru import logger

from .docker_runner import DockerRunner
from .misc import cfg_setter, tmux, tmux_shell, new_context


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DEBUGGER                                                                                            |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class Debugger(DockerRunner):
    def __init__(self, ctf_ctx: bool = False, **kwargs):
        super().__init__()
        cfg_setter(self, ["general", "debugger", "kernel_general"])
        if ctf_ctx:
            self.ctf_kernel = kwargs.get("ctf_kernel", "")
            self.project_dir = Path.cwd() / self.ctf_dir
            vmlinux = Path(self.project_dir) / "vmlinux"
            if not vmlinux.exists() or b"ELF" not in sp.run(f"file {vmlinux}", shell=True, capture_output=True).stdout:
                self.extract_vmlinux()
        else:
            self.project_dir = Path.cwd() / self.kernel_root
        self.ctf = int(ctf_ctx == True)
        self.custom_gdb_script = Path("/home/") / self.user / Path(self.gdb_script).name
        self.buildargs = {"USER": self.user}
        self.cli = docker.APIClient(base_url=self.docker_sock)

    def extract_vmlinux(self):
        with new_context(self.ctf_dir):
            vml_ext = glob("**/extract*", recursive=True)[0]
            ret = sp.run(f"./{vml_ext} {Path(self.ctf_kernel).name} > vmlinux", shell=True, capture_output=True)
            if ret.returncode == 0:
                logger.info("Successfully extracted 'vmlinux' from compressed kernel")
            else:
                logger.error("Failed to extract 'vmlinux'")
                exit(-1)

    def run_container(self) -> None:
        entrypoint = f"/home/{self.user}/debugger.sh -a {self.arch} -p {self.docker_mnt} -c {self.ctf} -g {self.custom_gdb_script}"
        runner = f'docker run -it --rm --security-opt seccomp=unconfined --cap-add=SYS_PTRACE -v {self.project_dir}:/io --net="host" {self.tag} {entrypoint}'
        tmux("selectp -t 2")
        tmux_shell(runner)

    def run(self):
        self.check_existing()
        super().run()
