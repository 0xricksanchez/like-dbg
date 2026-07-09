import pathlib


def test_src_is_slop_free():
    root = pathlib.Path(__file__).resolve().parents[1] / "src" / "likedbg"
    offenders = [
        f"{p.relative_to(root)}:{i} (U+{ord(c):04X})"
        for p in root.rglob("*.py")
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        for c in line
        if ord(c) > 0x7F
    ]
    assert not offenders, "non-ASCII slop in src/likedbg:\n" + "\n".join(offenders)
