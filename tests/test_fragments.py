import re
from pathlib import Path

FRAG = Path(__file__).parent.parent / "configs" / "fragments"
LINE = re.compile(r"^(CONFIG_[A-Z0-9_]+=[ymn]|CONFIG_[A-Z0-9_]+=\"?.*\"?|# CONFIG_[A-Z0-9_]+ is not set)$")


def test_fragments_exist():
    for name in ("debug.config", "no-kaslr.config", "generic.config"):
        assert (FRAG / name).is_file(), name


def test_fragment_lines_are_valid_kconfig():
    for f in FRAG.glob("*.config"):
        for raw in f.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") and "CONFIG_" not in line:
                continue
            assert LINE.match(line), f"{f.name}: bad line {line!r}"


def test_debug_enables_debug_info_and_gdb_scripts():
    text = (FRAG / "debug.config").read_text()
    assert "CONFIG_DEBUG_INFO_DWARF4=y" in text
    assert "CONFIG_GDB_SCRIPTS=y" in text


def test_no_kaslr_disables_randomize_base():
    assert "# CONFIG_RANDOMIZE_BASE is not set" in (FRAG / "no-kaslr.config").read_text()
