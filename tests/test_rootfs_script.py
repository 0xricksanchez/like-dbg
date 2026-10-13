from pathlib import Path

ROOTFS_SH = Path(__file__).resolve().parents[1] / "io" / "scripts" / "rootfs.sh"


def _script() -> str:
    return ROOTFS_SH.read_text()


def test_rootfs_default_packages_keep_ssh_and_compilers_without_plymouth():
    text = _script()
    pkgs = next(line for line in text.splitlines() if line.startswith("PKGS="))
    assert "build-essential" in pkgs
    assert "clang" in pkgs
    assert "openssh-server" in pkgs
    assert "plymouth" not in pkgs


def test_rootfs_uses_direct_ext4_population():
    text = _script()
    assert 'mkfs.ext4 -q -F -d "$MNT" "$ROOTFS_NAME"' in text
    assert "sudo mount -o loop" not in text


def test_rootfs_fstab_mounts_virtio_root_rw():
    text = _script()
    assert "/dev/vda / ext4 defaults 0 0" in text
    assert "/dev/root /" not in text


def test_rootfs_binfmt_registration_is_conditional():
    text = _script()
    assert 'if [ -r "$path" ]; then' in text
    assert 'update-binfmts --enable "$handler"' in text
    assert "find /proc/sys/fs/binfmt_misc -type f -name 'qemu-*'" not in text
    assert "binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0" not in text


def test_rootfs_generates_ed25519_ssh_key():
    text = _script()
    assert 'SSH_KEY="$ROOTFS_NAME.id_ed25519"' in text
    assert 'ssh-keygen -q -f "$SSH_KEY" -t ed25519' in text
