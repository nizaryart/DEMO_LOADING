"""Part C, slice C1 (2026-09-27): local file tools in the shadow engine.

The per-tool examples live in engine/rules.py and run in
test_engine_rules.py. This file holds what examples cannot express: each
rule's option grammar checked against the INSTALLED tool's own --help, and
verdict-level cases (zip-slip, WITHIN on the root vs a subdirectory,
devices, partial coverage). Each negative sits beside a control.
"""
import os
import re
import shutil
import subprocess
import zipfile

import pytest

from demo_cli.config import Config
from demo_cli.engine import predict
from demo_cli.engine.rules import C1_RULES, RULES

BY_ID = {r.id: r for r in RULES}
SEMANTIC_BUDGET_MS = 10_000


# ---- grammars, checked against the tool itself ----------------------------

HELP = {"cp": ["cp", "--help"], "mv": ["mv", "--help"], "ln": ["ln", "--help"],
        "install": ["install", "--help"], "tee": ["tee", "--help"],
        "touch": ["touch", "--help"], "mkdir": ["mkdir", "--help"],
        "truncate": ["truncate", "--help"], "shred": ["shred", "--help"],
        "sed": ["sed", "--help"], "tar": ["tar", "--help"], "wget": ["wget", "--help"],
        "curl": ["curl", "--help", "all"], "prettier": ["prettier", "--help"],
        "eslint": ["eslint", "--help"], "black": ["black", "--help"],
        "isort": ["isort", "--help"], "rustfmt": ["rustfmt", "--help"],
        "rsync": ["rsync", "--help"]}


def _long_options(text: str):
    """(required, optional): long options the help text shows taking a
    REQUIRED value (`--size=SIZE`, curl's `--output <file>`) or an OPTIONAL
    one (`--backup[=CONTROL]`), which only ever attaches with `=`."""
    required = set(re.findall(r"(--[a-z][\w-]*)=[A-Z]", text))
    required |= set(re.findall(r"(--[a-z][\w-]*) <[\w-]+>", text))
    optional = set(re.findall(r"(--[a-z][\w-]*)\[=", text))
    return required, optional


@pytest.mark.parametrize("rule_id", sorted(HELP))
def test_a_rules_grammar_matches_the_installed_tools_help(rule_id):
    rule = BY_ID[rule_id]
    argv = HELP[rule_id]
    if shutil.which(argv[0]) is None:
        pytest.skip(f"{argv[0]} is not installed here"
                    + ("" if rule.verified else " (grammar marked unverified)"))
    text = subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout
    required, optional = _long_options(text)
    assert required | optional, "control: the help text was read and parsed"
    missing = sorted(o for o in required if o not in rule.options.values)
    assert not missing, f"{rule_id}: value-taking options the rule does not know: {missing}"
    greedy = sorted(o for o in optional - required if o in rule.options.values)
    assert not greedy, f"{rule_id}: optional values would swallow the next word: {greedy}"


def test_unverified_grammars_are_marked():
    # C1's own rules (C2a adds mysql, pinned in test_engine_c2a.py)
    # M2.2f: rsync's grammar is VERIFIED now (rsync(1) of rsync 3.5.0)
    assert {r.id for r in C1_RULES if not r.verified} == \
        {"prettier", "eslint", "black", "isort", "rustfmt"}


# ---- verdicts ----------------------------------------------------------------

@pytest.fixture
def proj(tmp_path):
    for rel in ("a.txt", "b.txt", "dir/d.txt", "src/app.js"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
    return tmp_path


def _predict(root, command):
    """Meaning, not speed: the production budget is wall-clock and flaked
    under load (review 2026-09-28); see test_engine_rules.SEMANTIC_BUDGET_MS."""
    here = os.getcwd()
    os.chdir(str(root))
    try:
        return predict(command, Config(project_root=str(root)), budget_ms=SEMANTIC_BUDGET_MS)
    finally:
        os.chdir(here)


def _zip(path, members, encrypted=False, link=False):
    with zipfile.ZipFile(str(path), "w") as z:
        for name in members:
            info = zipfile.ZipInfo(name)
            if link:
                info.external_attr = 0o120777 << 16
            z.writestr(info, "x")
    if encrypted:
        # zipfile clears flag_bits when it writes, so set bit 0 ("encrypted")
        # in the bytes: the local header (offset 6) and the central directory (8).
        data = bytearray(path.read_bytes())
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            at = data.index(sig)
            data[at + off] |= 0x1
        path.write_bytes(bytes(data))
        with zipfile.ZipFile(str(path)) as z:
            assert z.infolist()[0].flag_bits & 0x1, "control: the bit is really set"


def test_zip_slip_is_destroyed_outside_and_escalates(proj):
    _zip(proj / "ok.zip", ["a.txt"])
    _zip(proj / "evil.zip", ["../outside.txt"])
    _zip(proj / "abs.zip", ["/tmp/abs-member.txt"])
    assert _predict(proj, "unzip -o ok.zip").decision == "REVERSIBLE", \
        "control: an in-project overwrite is a capture"
    assert _predict(proj, "unzip evil.zip").decision == "ESCALATE"
    assert _predict(proj, "unzip abs.zip").decision == "ESCALATE"


@pytest.mark.parametrize("kind", ["symlink", "encrypted", "corrupt", "too_many"])
def test_an_archive_we_cannot_trust_to_list_is_unknown(proj, kind):
    _zip(proj / "ok.zip", ["new.txt"])
    assert _predict(proj, "unzip ok.zip").decision == "ALLOW", "control: a readable archive"
    path = proj / "x.zip"
    if kind == "symlink":
        _zip(path, ["link"], link=True)
    elif kind == "encrypted":
        _zip(path, ["secret.txt"], encrypted=True)
    elif kind == "corrupt":
        path.write_bytes(b"this is not a zip archive")
    else:
        _zip(path, [f"f{i}.txt" for i in range(2001)])
    p = _predict(proj, "unzip x.zip")
    assert p.decision == "DEFER"
    assert p.impact.unknown


def test_within_on_a_subdirectory_is_a_capture_and_on_the_root_escalates(proj):
    p = _predict(proj, "find dir -name '*.txt' -delete")
    assert p.decision == "REVERSIBLE" and p.impact.within, "control: a subdirectory"
    p = _predict(proj, "find . -name '*.pyc' -delete")
    assert p.decision == "ESCALATE", "the project root is not captured whole, as today"
    assert p.impact.within


@pytest.mark.skipif(os.name == "nt", reason="no block devices under /dev on Windows")
def test_a_disk_is_a_remote_surface_and_the_sinks_are_not(proj):
    assert _predict(proj, "cat a.txt > /dev/null").decision == "ALLOW", "control: a sink"
    for sink in ("/dev/stderr", "/dev/fd/2", "/dev/tty", "/dev/zero"):
        assert _predict(proj, f"echo x > {sink}").decision == "ALLOW", sink
    for disk in ("cat a.txt > /dev/sda", "dd if=a.txt of=/dev/nvme0n1", "cp a.txt /dev/sdb"):
        p = _predict(proj, disk)
        assert p.decision == "ESCALATE" and p.impact.remote, disk


def test_the_network_side_is_modelled(proj):
    # M2.2b4a (msg 087): the request itself is modelled now (send_ops); a GET
    # reads, so nothing is left uncovered and nothing is reached.
    p = _predict(proj, "curl -o a.txt https://example.invalid/x")
    assert "a.txt" in {os.path.basename(k) for k in p.impact.destroys}, \
        "control: the file side is modelled"
    assert (list(p.impact.uncovered), dict(p.impact.remote)) == ([], {})
    w = _predict(proj, "wget https://example.invalid/a").impact
    assert (list(w.uncovered), dict(w.remote)) == ([], {})


def test_perl_without_in_place_is_uncovered_not_deferred(proj):
    p = _predict(proj, "perl -pi -e 's/x/y/' a.txt")
    assert p.decision == "REVERSIBLE", "control: -i rewrites the file"
    p = _predict(proj, "perl -ne 'print if /x/' a.txt")
    assert p.decision == "ALLOW" and not p.impact.unknown
    assert "perl (code)" in p.impact.uncovered


def _names(paths):
    return {os.path.basename(p) for p in paths}


def test_a_tools_backup_never_cancels_the_destruction(proj):
    """Review C1 (2026-09-28): the backup belongs to the TOOL. The agent's
    next command can delete it and demo_cli undo cannot restore from it, so
    the edited file's old content counts as destroyed."""
    assert _predict(proj, "sed s/x/y/ a.txt").decision == "ALLOW", "control: no -i, no edit"
    for cmd, backup in (("sed -i.bak s/x/y/ a.txt", "a.txt.bak"),
                        ("perl -pi.bak -e 's/x/y/' a.txt", "a.txt.bak"),
                        ("cp -b b.txt a.txt", "a.txt~"),
                        ("mv -b b.txt a.txt", "a.txt~"),
                        ("cp -S .old b.txt a.txt", "a.txt.old")):
        p = _predict(proj, cmd)
        assert p.decision == "REVERSIBLE", cmd
        assert _names(p.impact.destroys) == {"a.txt"} and _names(p.impact.creates) == {backup}, cmd


def test_a_numbered_backup_never_overwrites_an_older_backup(proj):
    (proj / "b.txt~").write_text("old backup")
    assert "b.txt~" in _names(_predict(proj, "cp -b a.txt b.txt").impact.destroys), \
        "control: a simple backup replaces the existing b.txt~"
    p = _predict(proj, "cp --backup=numbered a.txt b.txt")
    assert _names(p.impact.destroys) == {"b.txt"}
    assert _names(p.impact.creates) == {"b.txt.~1~"}


def test_a_known_destroy_outside_the_project_escalates_beside_an_unknown(proj):
    """Review C1 ruling 1: the filesystem layer covers the project folder
    only, so DEFER cannot save a known destroy outside it (or of its root)."""
    _zip(proj / "evil.zip", ["../outside.txt"])
    _zip(proj / "enc.zip", ["s.txt"], encrypted=True)
    p = _predict(proj, "rm a.txt; unzip enc.zip")
    assert p.decision == "DEFER" and _names(p.impact.destroys) == {"a.txt"}, \
        "control: a known destroy INSIDE the project beside an unknown still defers"
    p = _predict(proj, "unzip evil.zip; unzip enc.zip")
    assert p.impact.unknown and p.decision == "ESCALATE"
    p = _predict(proj, "find . -name '*.tmp' -delete; unzip enc.zip")
    assert p.impact.unknown and p.decision == "ESCALATE", "the project root"
