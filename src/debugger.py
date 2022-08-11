#!/usr/bin/env python3

from pathlib import Path

import docker

from .docker_runner import DockerRunner
from .misc import cfg_setter, tmux, tmux_shell


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DEBUGGER                                                                                            |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class Debugger(DockerRunner):
    def __init__(self):
        super().__init__()
        cfg_setter(self, ["general", "debugger", "kernel_general"])
        self.buildargs = {"USER": self.user}
        self.cli = docker.APIClient(base_url=self.docker_sock)

    def run_container(self) -> None:
        entrypoint = f"/home/{self.user}/debugger.sh -a {self.arch} -p {self.docker_mnt}"
        runner = f'docker run -it --rm --security-opt seccomp=unconfined --cap-add=SYS_PTRACE -v {Path.cwd() / self.kernel_root}:/io --net="host" {self.tag} {entrypoint}'
        tmux("selectp -t 2")
        tmux_shell(runner)

    def run(self):
        self.check_existing()
        super().run()
