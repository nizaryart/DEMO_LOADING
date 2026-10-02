"""One parse of a POSIX command line (model.py), read by everything.

WHY THIS EXISTS. The audit and review of 2026-09-26/27 kept finding the same
shape of defect: two parsers answering one question differently - the
splitter, the command-word normalizer, the quote masker, the heredoc reader,
the operand tokenizer. Two of those were introduced by fixes to the others.
classify._effective_segments now serves one parse to the classifier and to
target resolution.

HOW IT WAS LANDED. The parse ran in shadow first. Over every command the
suite classifies (801, both dialects) it gave the same decision as the text
splitter on every one. Over a hand-labelled set of what bash actually runs
(below) it was right in 22 cases the splitter got wrong and wrong in none the
splitter got right. Both numbers are the reason it replaced the splitter
rather than joining it.
"""
import os

import pytest

from demo_cli.classify import classify_pipeline, redirect_target
from demo_cli.config import Config
from demo_cli.guard import Guard
from demo_cli.model import parse, posix_units

# (command, does bash run something the rules call destructive or mutating?)
# "splitter" marks the rows the text splitter got wrong.
WHAT_RUNS = [
    # comments are not commands
    ("ls # ; rm -rf x", False),                                   # splitter
    ("# rm -rf /", False),                                        # splitter
    ("echo foo #; rm -rf x", False),                              # splitter
    ("true && # note\nrm -rf x", True),
    ('echo "# not a comment"; rm x', True),
    ("echo a#b; rm x", True),
    # substitutions are commands, found by parsing
    ("echo $(date; rm -rf x) >/dev/null", True),
    ("echo $(ls | wc -l) > /dev/null", False),
    ("x=$(rm y) ls", True),                                       # splitter
    ("echo `rm y`", True),                                        # splitter
    ("diff <(rm y) z", True),                                     # splitter
    ("echo ${x:-$(rm y)}", True),                                 # splitter
    ("echo $(( $(rm y) + 1 ))", True),                            # splitter
    ("echo '$(rm y)'", False),
    ('echo "$(rm y)"', True),                                     # splitter
    ('git commit -m "$(rm y)"', True),                            # splitter
    ("git commit -m 'uses $(rm y)'", False),
    ("for f in $(rm y); do :; done", True),                       # splitter
    ("timeout $(rm y) ls", True),                                 # splitter
    # heredocs
    ("cat <<EOF > n.md\n# note $(rm y)\nEOF", True),
    ("cat <<'EOF' >/dev/null\n# note $(rm y)\nEOF", False),
    ("bash <<'EOF'\n# comment\nrm y\nEOF", True),
    ("cat <<'EOF' >/dev/null\nrm y\nEOF", False),
    # nested shells
    ('bash -o pipefail -c "rm app.db"', True),                    # splitter
    ('bash -O extglob -c "rm app.db"', True),                     # splitter
    ('bash --norc -c "rm app.db"', True),
    ('sh -ec "rm app.db"', True),
    ('bash -c "echo \\$(rm y)"', True),                           # splitter
    ("bash -c 'echo hi # ; rm y'", False),                        # splitter
    # separators
    ("echo hi; rm x", True), ("a && rm x", True), ("a || rm x", True),
    ("rm x &", True), ("echo 'a; rm x'", False),
    ("echo a\\; rm x", False),                                    # splitter
    # redirects
    ("> app.db", True), ("echo x >> log", False), ("echo x 2>&1", False),
    ("echo x >/dev/null", False), ("echo x >&-", False),
    ("echo x >& out.txt", True),                                  # splitter
    # keywords, clauses, wrappers
    ("for f in a b; do rm $f; done", True),
    ("if true; then rm x; fi", True),
    ("case $x in a) rm x;; esac", True),                          # splitter
    ("f() { rm x; }; f", True),                                   # splitter
    ("function f { rm x; }", True),
    ("select x in a; do rm $x; done", True),
    ("time -p rm x", True),
    ('X="a b" rm y', True),                                       # splitter
    ("sudo -u root rm x", True),
    ("command -v rm", False),
    # found after the parse landed: all three were caught by the text
    # splitter and ALLOWed by the parse (2026-09-27 re-review)
    ("> out.txt echo hi", True),                                  # regression
    (">out.txt cat in.txt", True),                                # regression
    ("2>/dev/null >out.txt echo hi", True),                       # regression
    ("2>/dev/null echo hi", False),                               # control
    ("bash -c 'sh' <<EOF\nrm -rf dir\nEOF", True),                # regression
    ("bash -c 'cat' <<'EOF'\nrm -rf dir\nEOF", False),            # control
    ("env -S 'rm -rf dir'", True),                                # regression
    ("env -S'rm -rf dir'", True),                                 # regression
    ("env --split-string='rm -rf dir'", True),                    # regression
    ('env -S "rm x"', True),
    ("env -S 'echo hi'", False),                                  # control
    ("env -u FOO rm x", True),
]


@pytest.mark.parametrize("cmd,runs", WHAT_RUNS)
def test_the_verdict_follows_what_bash_runs(cmd, runs):
    r = classify_pipeline(cmd)
    assert (r.needs_recovery or r.remote_exec) is runs, (cmd, r.segments)


# ---------------------------------------------------------------- end to end

@pytest.fixture()
def proj(tmp_path, monkeypatch):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    p = tmp_path / "proj"
    p.mkdir()
    (p / "x.txt").write_text("keep")
    monkeypatch.chdir(p)
    return p


def _guard(root):
    return Guard(Config(project_root=str(root)), mode="enforce")


def test_a_commented_out_delete_is_allowed_and_touches_nothing(proj):
    g = _guard(proj)
    assert g.evaluate("rm x.txt").decision.decision == "REVERSIBLE", "control"
    r = g.evaluate("ls # ; rm x.txt")
    assert r.decision.decision == "ALLOW" and not r.recovery_entry


def test_a_delete_inside_a_substitution_is_not_waved_through(proj):
    """`$(rm x.txt)` was invisible unless rm carried both -r and -f."""
    r = _guard(proj).evaluate('git commit -m "$(rm x.txt)"')
    assert r.decision.decision != "ALLOW", r.decision.reason


def test_the_stdout_and_stderr_redirect_is_captured(proj):
    r = _guard(proj).evaluate("echo x >& x.txt")
    assert r.decision.decision == "REVERSIBLE", r.decision.reason
    assert r.target.ref == str(proj / "x.txt")


def test_a_bash_option_with_a_value_does_not_hide_the_payload(proj):
    r = _guard(proj).evaluate('bash -o pipefail -c "rm x.txt"')
    assert r.decision.decision == "REVERSIBLE", r.decision.reason
    assert r.target.ref == str(proj / "x.txt")


def test_a_redirect_before_the_command_word_is_captured(proj):
    """`> x.txt echo hi` truncates x.txt. The unit used to start at the
    command word and drop the redirect: ALLOW, nothing captured."""
    g = _guard(proj)
    assert g.evaluate("> new.txt echo hi").decision.decision == "ALLOW", "control: creates"
    r = g.evaluate("> x.txt echo hi")
    assert r.decision.decision == "REVERSIBLE", r.decision.reason
    assert r.target.ref == str(proj / "x.txt")


def test_a_prefix_redirect_beside_a_delete_is_not_a_one_file_recovery(proj):
    """`>x.txt rm y.txt` destroys two files. Under S2, both are captured
    together in a group snapshot (REVERSIBLE), never a one-file partial recovery."""
    (proj / "y.txt").write_text("keep")
    g = _guard(proj)
    assert g.evaluate("rm y.txt").decision.decision == "REVERSIBLE", "control"
    r = g.evaluate(">x.txt rm y.txt")
    x_bytes = (proj / "x.txt").read_bytes()
    expected = "REVERSIBLE" if ENGINE_PATH else "ESCALATE"
    assert r.decision.decision == expected, r.decision.reason
    if ENGINE_PATH:
        assert_restores(r.recovery_entry, proj, {"x.txt": x_bytes, "y.txt": b"keep"})
    else:
        assert not r.recovery_entry


def test_env_split_string_is_the_command_it_runs(proj):
    g = _guard(proj)
    assert g.evaluate("env -S 'echo hi'").decision.decision == "ALLOW", "control"
    r = g.evaluate("env -S 'rm x.txt'")
    assert r.decision.decision == "REVERSIBLE", r.decision.reason
    assert r.target.ref == str(proj / "x.txt")


# ------------------------------------------------------------- the parse

def test_a_pipe_inside_a_substitution_does_not_split_the_command():
    units = [t for t, _d, _s in posix_units("echo $(ls | wc -l) > count.txt")]
    assert "echo $(" in units[-1] and units[-1].endswith("> count.txt"), units


def test_a_heredoc_body_is_attached_to_its_redirect():
    cmd = parse("cat <<'EOF' > notes.md\ngit push --force\nEOF\nrm y").commands
    assert [w.value for w in cmd[0].argv] == ["cat"]
    hd = next(r.heredoc for r in cmd[0].redirects if r.heredoc)
    assert hd.body == "git push --force" and hd.quoted
    assert [w.value for w in cmd[1].argv] == ["rm", "y"]


def test_a_quoted_payload_is_what_the_inner_shell_receives():
    cm = parse('bash -c "echo \\$(rm y)"').commands[0]
    assert cm.nested is not None
    assert cm.argv[2].value == "echo $(rm y)"


def test_redirect_target_tells_duplication_from_a_file():
    assert redirect_target("echo x 2>&1") is None
    assert redirect_target("echo x >&-") is None
    assert redirect_target("echo x >& out.txt") == "out.txt"
    assert redirect_target("cmd 2>&1 > log.txt") == "log.txt"


def test_nesting_is_bounded():
    deep = 'bash -c "' * 20 + "rm x" + '"' * 20
    posix_units(deep)                         # must return, not recurse forever
