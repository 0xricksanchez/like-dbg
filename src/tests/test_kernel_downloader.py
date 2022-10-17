from ..linux_kernel_dl import KernelDownloader
from pathlib import Path
import requests
import hashlib


def test_uris():
    lkdl = KernelDownloader()
    assert lkdl.commit_uri == "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/"
    assert lkdl.snap_uri == "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-"
    assert lkdl.mmp_uri == "https://cdn.kernel.org/pub/linux/kernel/vKMAJOR.x/linux-KMAJOR.KMINOR.KPATCH.tar.xz"


def test_mmp() -> None:
    lkdl = KernelDownloader(**{"user_cfg": str(Path("./src/tests/confs/lkdl_mmp.ini").absolute())})
    assert lkdl.mmp == "5.15.67"
    dl_uri = lkdl._set_dl_uri()
    assert dl_uri == f"https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-{lkdl.mmp}.tar.xz"
    resp = requests.head(dl_uri).headers
    assert resp["Content-Type"] == "application/x-xz"


def test_tag() -> None:
    lkdl = KernelDownloader(**{"user_cfg": str(Path("./src/tests/confs/lkdl_tag.ini").absolute())})
    assert lkdl.tag == "5.15-rc2"
    dl_uri = lkdl._set_dl_uri()
    assert dl_uri == f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-{lkdl.tag}.tar.gz"
    resp = requests.head(dl_uri).headers
    assert resp["Content-Type"] == "application/x-gzip; charset=UTF-8"


def test_commit() -> None:
    lkdl = KernelDownloader(**{"user_cfg": str(Path("./src/tests/confs/lkdl_commit.ini").absolute())})
    assert lkdl.commit == "e4e737bb5c170df6135a127739a9e6148ee3da82"
    assert lkdl.commit != lkdl._resolve_latest()
    dl_uri = lkdl._set_dl_uri()
    assert dl_uri == f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-{lkdl.commit}.tar.gz"
    resp = requests.head(dl_uri).headers
    assert resp["Content-Type"] == "application/x-gzip; charset=UTF-8"


def test_version_hierachy() -> None:
    lkdl = KernelDownloader()
    lkdl.mmp = "5.15.67"
    lkdl.tag = "5.15-rc2"
    lkdl.commit = "e4e737bb5c170df6135a127739a9e6148ee3da82"
    assert lkdl._set_choice() == lkdl.mmp
    lkdl.mmp = None
    assert lkdl._set_choice() == lkdl.tag
    lkdl.tag = None
    assert lkdl._set_choice() == lkdl.commit
    lkdl.mmp = "5.15.67"
    assert lkdl._set_choice() == lkdl.mmp


def test_is_present() -> None:
    lkdl = KernelDownloader()
    lkdl.archive = Path("/bin/ls")
    assert lkdl.run() == lkdl.archive


def test_run(tmp_path):
    lkdl = KernelDownloader(**{"user_cfg": str(Path("./src/tests/confs/lkdl_tag.ini").absolute())})
    lkdl.kernel_dl_path = tmp_path
    lkdl.archive = Path(lkdl.kernel_dl_path) / f"linux-{lkdl._set_choice()}.tar.gz"
    lkdl.dl_uri = "https://file-examples.com/wp-content/uploads/2017/02/zip_2MB.zip"
    lkdl.run()
    assert hashlib.md5(lkdl.archive.read_bytes()).hexdigest() == "3bcc73cf17293dae9ae3003bc82bd11f"
