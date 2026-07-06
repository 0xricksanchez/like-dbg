from pathlib import Path

from likedbg.input_hash import DEFAULT_IGNORE
from likedbg.input_hash import hash_file
from likedbg.input_hash import hash_tree


def test_hash_file_is_sha256_of_content(tmp_path: Path) -> None:
    f = tmp_path / "a.txt"
    f.write_bytes(b"hello")
    # sha256("hello")
    assert hash_file(f) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_hash_tree_is_order_independent_and_content_sensitive(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.c").write_text("b")
    (tmp_path / "a.c").write_text("a")
    first = hash_tree(tmp_path)
    # Rewriting identical content yields the same aggregate.
    (tmp_path / "a.c").write_text("a")
    assert hash_tree(tmp_path).aggregate == first.aggregate
    # Records are sorted by relative path.
    assert [rel for rel, _ in first.files] == ["a.c", "sub/b.c"]
    # A content change moves the aggregate.
    (tmp_path / "a.c").write_text("A")
    assert hash_tree(tmp_path).aggregate != first.aggregate


def test_hash_tree_ignores_build_junk(tmp_path: Path) -> None:
    (tmp_path / "keep.c").write_text("x")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref")
    (tmp_path / "m.o").write_text("obj")
    (tmp_path / ".DS_Store").write_text("junk")
    (tmp_path / ".m.o.cmd").write_text("cmd litter")  # kbuild .cmd litter, see .gitignore
    th = hash_tree(tmp_path, ignore=DEFAULT_IGNORE)
    assert [rel for rel, _ in th.files] == ["keep.c"]


def test_hash_tree_empty_dir_is_stable(tmp_path: Path) -> None:
    assert hash_tree(tmp_path).aggregate == hash_tree(tmp_path).aggregate
    assert hash_tree(tmp_path).files == ()
