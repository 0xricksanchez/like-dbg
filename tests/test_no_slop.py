import pathlib


def test_src_is_slop_free():
    root = pathlib.Path(__file__).resolve().parents[1] / "src" / "likedbg"
    bad = {"—": "em-dash", "–": "en-dash", "…": "ellipsis"}
    offenders = [
        f"{p.relative_to(root)}:{i} ({bad[c]})"
        for p in root.rglob("*.py")
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        for c in line
        if c in bad
    ]
    assert not offenders, "non-ASCII slop in src/likedbg:\n" + "\n".join(offenders)
