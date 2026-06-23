from likedbg import constants


def test_volume_and_mount_values():
    assert constants.KERNEL_VOLUME == "likedbg_ksrc"
    assert constants.VOLUME_MOUNT == "/ksrc"


def test_image_tags_are_tagged_latest():
    # All image identifiers carry an explicit :latest tag for one consistent convention.
    for tag in (
        constants.BASE_IMAGE,
        constants.KBUILDER_IMAGE,
        constants.ROOTFS_IMAGE,
        constants.DEBUGGER_IMAGE,
        constants.DEBUGGEE_IMAGE,
    ):
        assert tag.endswith(":latest")


def test_base_image_is_like_dbg_base():
    assert constants.BASE_IMAGE == "like_dbg_base:latest"


def test_debuggee_image_value():
    assert constants.DEBUGGEE_IMAGE == "like_debuggee:latest"
