import likedbg


def test_package_exposes_version():
    assert isinstance(likedbg.__version__, str)
    assert likedbg.__version__
