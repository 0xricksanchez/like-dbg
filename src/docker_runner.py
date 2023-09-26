import os
import subprocess as sp
import time
from pathlib import Path

import docker
from docker.models.images import Image
from fabric import Connection
from loguru import logger

from src.misc import cfg_setter, is_reuse


# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
# | DOCKER RUNNER                                                                                       |
# +-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+
class DockerRunner:
    def __init__(self, **kwargs) -> None:
        self.skip_prompts = kwargs.get("skip_prompts", False)
        self.update_containers = kwargs.get("update_containers", False)
        self.ctf = kwargs.get("ctf_ctx", False)
        self.ssh_conn = None
        self.image = None
        self.tag = None
        self.ssh_fwd_port = None
        self.container = None
        cfg_setter(self, ["general"], user_cfg="", exclude_keys=[])
        self.buildargs = {"USER": self.user}
        self.dockerfile_ctx = Path.cwd()
        self.client = docker.from_env()
        self.cli = docker.APIClient(base_url=self.docker_sock)
        if not kwargs.get("ctf_ctx", False):
            self.kernel_root = kwargs.get("kroot", None)
            if not self.kernel_root:
                logger.critical(f"{type(self).__name__} got invalid kernel root: '{self.kernel_root}'")
                exit(-1)

    def guarantee_ssh(self, ssh_dir: Path) -> str:
        if Path(ssh_dir).exists() and "like.id_rsa" in os.listdir(ssh_dir):
            logger.debug(f"Reusing local ssh keys from {ssh_dir}...")
        else:
            logger.debug("Generating new ssh key pair...")
            if not Path(ssh_dir).exists():
                Path(ssh_dir).mkdir()
            sp.run(f'ssh-keygen -f {Path(ssh_dir) / "like.id_rsa"} -t rsa -N ""', shell=True)
        return ssh_dir

    def init_ssh(self):
        tries = 0
        while True:
            try:
                self.ssh_conn = Connection(
                    f"{self.user}@localhost:{self.ssh_fwd_port}", connect_kwargs={"key_filename": ".ssh/like.id_rsa"}
                )
            except Exception as e:
                tries += 1
                logger.error(f"Failed to initialize SSH connection to {type(self).__name__}: {e}")
                logger.error("Retrying in 5 seconds...")
                if tries >= 5:
                    logger.critical(f"{tries} attempts failed! Exiting...")
                    exit(-1)
                time.sleep(5)
            else:
                logger.debug("Established SSH connection!")
                break

    def build_image(self, dockerfile=None, buildargs=None, image_tag=None):
        dockerfile = dockerfile if dockerfile else self.dockerfile
        buildargs = buildargs if buildargs else self.buildargs
        tag = image_tag if image_tag else self.tag
        nocache = True if self.update_containers else False
        try:
            for log_entry in self.cli.build(
                path=str(self.dockerfile_ctx),
                dockerfile=dockerfile,
                tag=tag,
                decode=True,
                buildargs=buildargs,
                nocache=nocache,
                rm=True,
            ):
                v = next(iter(log_entry.values()))
                if isinstance(v, str):
                    v = " ".join(v.strip().split())
                    if v and not self.update_containers:
                        logger.debug(v)
                    elif v and self.update_containers:
                        logger.info(v)
            if self.update_containers:
                self.cli.prune_images(filters={"dangling": True})
            return 0
        except docker.errors.APIError:
            return 1

    def get_image(self, tag=None) -> Image:
        to_check = tag if tag else self.tag
        try:
            return self.client.images.get(to_check)
        except docker.errors.ImageNotFound:
            return None

    def is_base_image(self) -> bool:
        if self.get_image(tag=self.tag_base_image):
            return True
        else:
            return False

    def build_base_img(self) -> int:
        return self.build_image(dockerfile=self.dockerfile_base_img, image_tag=self.tag_base_image)

    def run(self, check_existing: bool = False) -> int:
        if self.update_containers:
            self.build_image()
            return 1
        if check_existing:
            self.check_existing()
        if not self.image:
            if not self.is_base_image():
                logger.debug("Could not find 'like-dbg'-base image! Building it!")
                self.build_base_img()
            logger.info(f"Building fresh image for {type(self).__name__}")
            self.build_image()
            self.image = self.get_image()
        self.run_container()
        return 0

    def run_container(self) -> None:
        pass

    def stop_container(self) -> None:
        self.container.stop()

    def list_running_containers(self) -> list[docker.client.DockerClient.containers]:
        return self.client.containers.list()

    # This one requires a HEALTHCHECK in the dockerfile
    def wait_for_container(self) -> None:
        logger.info("Waiting for Container to be up...")
        while True:
            c = self.cli.inspect_container(self.container.id)
            if c["State"]["Health"]["Status"] != "healthy":
                time.sleep(1)
            else:
                break

    def pull_image(self, repo: str, tag: None) -> Image:
        tag = tag if tag else self.tag
        return self.client.images.pull(repo, tag=tag)

    def check_existing(self) -> Image:
        if self.update_containers:
            return None
        if self.force_rebuild:
            logger.info(f"Force-rebuilding {type(self).__name__}")
            self.image = None
            return self.image
        self.image = self.get_image()
        if self.image and self.skip_prompts:
            return self.image
        if self.image and not is_reuse(self.image.tags[0]):
            self.image = None
        return self.image
