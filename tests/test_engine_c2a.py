"""Part C2a (2026-09-28): SQL clients in the shadow engine.

The per-client examples live in engine/rules.py and run in
test_engine_rules.py. This file holds what examples cannot express: the SQL
splitter and classifier; the review C2 rulings (R2 redaction, R4 overlay
reads and the size cap, Q1's remote policy, Q3 bare SQL, Q5 ATTACH, Q6 one
set); DIFFERENTIAL tests that run the real sqlite3 / PostgreSQL and compare
what changed with what was predicted; each TODAY_MISS row; and the grammars
against the installed tools' --help. Each negative sits beside a control.
"""
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time

import pytest

from demo_cli.config import Config
from demo_cli.engine import predict
from demo_cli.engine.effects import DELETE, OVERWRITE, CREATE, RUN, Impact
from demo_cli.engine.rules import RULES

# Module-level imports are only what existed before C2a, so the controls also
# run on the previous tree (fail-on-old). New names are imported in the tests.
READ, WRITE, UNKNOWN = "READ", "WRITE", "UNKNOWN"


def split(text, dialect, budget):
    from demo_cli.engine.sql import split as f
    return f(text, dialect, budget)


def classify(text, dialect):
    from demo_cli.engine.sql import classify as f
    return f(text, dialect)

SEMANTIC_BUDGET_MS = 10_000          # meaning, not speed (the flaky-test fix)


class _NoBudget:
    def check(self):
        pass


@pytest.fixture
def proj(tmp_path):
    con = sqlite3.connect(str(tmp_path / "app.db"))
    con.execute("CREATE TABLE t(a)")
    con.execute("INSERT INTO t VALUES (1), (2)")
    con.commit()
    con.close()
    (tmp_path / "q.sql").write_text("DELETE FROM t;\n")
    (tmp_path / "r.sql").write_text("SELECT 1;\n")
    (tmp_path / "a.txt").write_text("a\n")
    (tmp_path / "sub").mkdir()
    return tmp_path


def _predict(root, command, **kw):
    here = os.getcwd()
    os.chdir(str(root))
    try:
        return predict(command, Config(project_root=str(root)), budget_ms=SEMANTIC_BUDGET_MS, **kw)
    finally:
        os.chdir(here)


# ---- the splitter -------------------------------------------------------------------

def _pieces(text, dialect="postgres"):
    return split(text, dialect, _NoBudget())


def test_statements_split_on_the_delimiter_outside_quotes_and_comments():
    assert _pieces("SELECT 1; SELECT 2;") == [("SELECT 1", False), ("SELECT 2", False)], \
        "control: two statements"
    assert _pieces("SELECT 'a;b'; SELECT 2") == [("SELECT 'a;b'", False), ("SELECT 2", False)]
    assert _pieces("SELECT 'it''s;'; x") == [("SELECT 'it''s;'", False), ("x", False)]
    assert _pieces("SELECT $$a;b$$; x") == [("SELECT $$a;b$$", False), ("x", False)]
    assert _pieces("SELECT $f$a;b$f$; x") == [("SELECT $f$a;b$f$", False), ("x", False)]
    assert _pieces("SELECT 1 -- a;b\n; x") == [("SELECT 1", False), ("x", False)]
    assert _pieces("SELECT /* a;b */ 1; x") == [("SELECT   1", False), ("x", False)]
    assert _pieces("SELECT $1, $2; x") == [("SELECT $1, $2", False), ("x", False)], \
        "a parameter is not a dollar quote"


def test_an_unterminated_quote_is_one_unknown_piece():
    st = classify(_pieces("DELETE FROM t WHERE a = 'x; DROP TABLE t")[-1][0], "postgres")
    assert st.kind == UNKNOWN
    assert classify("DELETE FROM t", "postgres").kind == WRITE, "control"


def test_client_commands_are_whole_lines():
    assert _pieces(".shell rm a.txt\nDELETE FROM t;", "sqlite") == \
        [(".shell rm a.txt", True), ("DELETE FROM t", False)]
    assert _pieces("SELECT 1;\n\\! rm a.txt\nSELECT 2;") == \
        [("SELECT 1", False), ("\\! rm a.txt", True), ("SELECT 2", False)]
    assert _pieces("SELECT 'x.y';", "sqlite") == [("SELECT 'x.y'", False)], \
        "control: a dot inside a statement is not a command"


def test_mysql_delimiter_changes_the_splitter():
    got = _pieces("delimiter //\nCREATE PROCEDURE p() BEGIN DELETE FROM t; END//\nSELECT 1//",
                  "mysql")
    assert got[0] == ("delimiter //", True)
    assert got[1][0].startswith("CREATE PROCEDURE") and got[1][0].endswith("END")
    assert got[2] == ("SELECT 1", False)


# ---- the classifier (VERIFIED semantics: see sql.py) --------------------------------------

@pytest.mark.parametrize("stmt,dialect,kind,effect", [
    ("SELECT * FROM t", "postgres", READ, None),
    ("DELETE FROM t", "postgres", WRITE, DELETE),
    ("DROP TABLE t", "sqlite", WRITE, DELETE),
    ("TRUNCATE t", "postgres", WRITE, DELETE),
    ("UPDATE t SET a = 1", "postgres", WRITE, OVERWRITE),
    ("INSERT INTO t VALUES (1)", "postgres", WRITE, OVERWRITE),
    ("CREATE TABLE t2(a)", "postgres", WRITE, CREATE),
    ("CREATE OR REPLACE VIEW v AS SELECT 1", "postgres", WRITE, OVERWRITE),
    ("EXPLAIN DELETE FROM t", "postgres", READ, None),
    ("EXPLAIN ANALYZE DELETE FROM t", "postgres", WRITE, DELETE),
    ("EXPLAIN (ANALYZE, BUFFERS) UPDATE t SET a = 1", "postgres", WRITE, OVERWRITE),
    ("EXPLAIN (ANALYZE off) DELETE FROM t", "postgres", READ, None),
    ("EXPLAIN QUERY PLAN DELETE FROM t", "sqlite", READ, None),
    ("WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", "postgres", WRITE, DELETE),
    ("WITH x AS (SELECT 1) SELECT * FROM x", "postgres", READ, None),
    ("SELECT * INTO t2 FROM t", "postgres", WRITE, CREATE),
    ("SELECT a INTO @v FROM t", "mysql", READ, None),
    ("SELECT a INTO OUTFILE '/tmp/x' FROM t", "mysql", UNKNOWN, None),
    ("SELECT setval('s', 1)", "postgres", WRITE, OVERWRITE),
    ("SELECT load_extension('x')", "sqlite", UNKNOWN, None),
    ("PRAGMA table_info(t)", "sqlite", READ, None),
    ("PRAGMA journal_mode = WAL", "sqlite", WRITE, OVERWRITE),
    ("COPY t TO STDOUT", "postgres", READ, None),
    ("COPY t FROM '/tmp/x.csv'", "postgres", WRITE, OVERWRITE),
    ("COPY t TO '/tmp/x.csv'", "postgres", UNKNOWN, None),
    ("CALL cleanup()", "postgres", UNKNOWN, None),
    ("BEGIN", "postgres", READ, None),
    ("ROLLBACK", "postgres", READ, None),
    ("GRANT ALL ON t TO public", "postgres", WRITE, OVERWRITE),
    ("FROBNICATE t", "postgres", UNKNOWN, None),
])
def test_a_statement_is_classified_by_what_it_does(stmt, dialect, kind, effect):
    st = classify(stmt, dialect)
    assert (st.kind, st.effect) == (kind, effect)


def test_the_splitter_checks_the_budget():
    from demo_cli.engine.simulate import Budget, BudgetExceeded
    text = "SELECT 1;\n" * 2000
    assert len(split(text, "postgres", Budget(SEMANTIC_BUDGET_MS))) == 2000, "control"

    class Spent:
        def check(self):
            raise BudgetExceeded()
    with pytest.raises(BudgetExceeded):
        split(text, "postgres", Spent())


# ---- R4: reads through the overlay, and the size cap ----------------------------------------

def test_sql_read_from_a_file_follows_the_overlay(proj):
    p = _predict(proj, "sqlite3 app.db < q.sql")
    assert p.decision == "REVERSIBLE" and not p.impact.unknown, "control: q.sql is read"
    p = _predict(proj, "echo 'SELECT 1;' > q.sql; sqlite3 app.db < q.sql")
    assert p.impact.unknown, "q.sql is rewritten earlier on the line: its content is unknown"
    p = _predict(proj, "mv q.sql moved.sql && sqlite3 app.db < moved.sql")
    assert not p.impact.unknown and p.decision == "REVERSIBLE", "a moved file is read at its origin"


def test_sql_over_the_cap_is_unknown_and_a_may_write(proj):
    from demo_cli.engine.sqlclients import MAX_SQL_BYTES
    (proj / "small.sql").write_text("SELECT 1;\n")
    assert not _predict(proj, "sqlite3 app.db < small.sql").impact.unknown, "control"
    (proj / "big.sql").write_text("SELECT 1;\n" * (MAX_SQL_BYTES // 10 + 1))
    p = _predict(proj, "sqlite3 app.db < big.sql")
    assert p.impact.unknown and p.decision == "DEFER"
    assert any(k.endswith("app.db") for k in p.impact.destroys), "may-write: the db is in the set"


# ---- R2: redaction ------------------------------------------------------------------------------

def test_receipts_redact_dict_keys_too():
    from demo_cli.receipts import _redacted
    url = "postgres://u:s3cret@db.example.com/app"
    assert "s3cret" not in json.dumps(_redacted({"x": url})), "control: a value is redacted"
    assert "s3cret" not in json.dumps(_redacted({url: "DELETE"}))
    assert "s3cret" not in json.dumps(_redacted([{"remote": {url: "DELETE"}}]))


def test_a_database_label_never_carries_a_password(proj):
    from demo_cli.guard import Guard, agent_directory
    cmd = "psql postgres://u:s3cret@db.example.com/app -c 'DELETE FROM t'"
    with agent_directory(str(proj)):
        r = Guard(config=Config(project_root=str(proj), mode="shadow")).evaluate(cmd, dialect="posix")
    assert r.prediction["remote"] == {"db:db.example.com/app": "DELETE"}
    assert "s3cret" in cmd, "control: the secret is really in the command"
    with open(str(proj / ".demo_cli" / "receipts.jsonl")) as f:
        last = f.read().splitlines()[-1]
    assert "s3cret" not in last


# ---- Q3: a bare SQL line (the check door) ----------------------------------------------------------

def test_a_bare_sql_line_runs_against_the_check_doors_target(proj):
    assert _predict(proj, "SELECT * FROM t").decision == "ALLOW", "control: a read"
    p = _predict(proj, "DELETE FROM t", explicit_db="app.db")
    assert p.decision == "REVERSIBLE" and {os.path.basename(k) for k in p.impact.destroys} == {"app.db"}
    p = _predict(proj, "delete from t", db_url="postgres://localhost/db")
    assert p.impact.databases == {"db:localhost/db": "DELETE"}
    p = _predict(proj, "DELETE FROM users")
    assert p.decision == "ESCALATE" and p.impact.no_capture, "no database named: no capture path"


def test_a_lowercase_word_without_a_target_is_still_a_shell_command(proj):
    p = _predict(proj, "delete from t")
    assert not p.impact.no_capture and "delete" in p.impact.uncovered


def test_the_guard_passes_the_check_doors_target(proj):
    from demo_cli.guard import Guard, agent_directory
    with agent_directory(str(proj)):
        r = Guard(config=Config(project_root=str(proj), mode="shadow")).evaluate(
            "DELETE FROM t", dialect="posix", explicit_db=str(proj / "app.db"))
    assert r.prediction["decision"] == "REVERSIBLE"
    assert list(r.prediction["destroys"]) == ["app.db"]


# ---- Q1: one policy table ------------------------------------------------------------------

def test_the_remote_policy_table():
    from demo_cli.engine.effects import REF, SEND, SERVICE_KEEP, SERVICE_LOSS  # M2.2a (msg 065): ruling (c)
    from demo_cli.engine.verdict import REMOTE_POLICY, verdict
    assert REMOTE_POLICY == {DELETE: "ESCALATE", OVERWRITE: "ESCALATE", SEND: "ESCALATE",
                             RUN: "ESCALATE", SERVICE_LOSS: "ESCALATE", SERVICE_KEEP: "ALLOW",
                             CREATE: "ALLOW", REF: "ALLOW"}  # M2.2a (msg 065): ruling (c)
    cfg = Config(project_root="/nonexistent-project")
    imp = Impact()
    imp.reach("db:h/app", OVERWRITE)
    assert verdict(imp, cfg)[0] == "ESCALATE", "control"
    for kind in (CREATE, SERVICE_KEEP):
        imp = Impact()
        imp.reach("x:h", kind)
        decision, why = verdict(imp, cfg)
        assert decision == "ALLOW" and "listed" in why, kind


def test_the_same_surface_twice_keeps_the_kind_that_loses_most():
    imp = Impact()
    assert imp.remote in ({}, set()), "control: an empty Impact"
    imp.reach("db:h/app", CREATE)
    imp.reach("db:h/app", DELETE)
    imp.reach("db:h/app", OVERWRITE)
    assert imp.remote == {"db:h/app": DELETE}


# ---- Q5 ATTACH, Q6 one set ----------------------------------------------------------------------

def test_attaching_a_literal_file_outside_the_project_is_a_known_outside_destroy(proj, tmp_path_factory):
    outside = tmp_path_factory.mktemp("elsewhere") / "o.db"
    outside.write_text("x")
    (proj / "in.db").write_text("x")
    p = _predict(proj, "sqlite3 app.db \"ATTACH 'in.db' AS o; DELETE FROM o.t\"")
    assert p.decision == "REVERSIBLE", "control: inside the project, the set grows"
    p = _predict(proj, f"sqlite3 app.db \"ATTACH '{outside}' AS o; DELETE FROM o.t\"")
    assert p.decision == "ESCALATE" and str(outside) in p.impact.destroys


def test_a_database_and_files_are_one_set(proj):
    p = _predict(proj, "psql postgres://localhost/db -c 'DELETE FROM t'; rm a.txt")
    assert p.decision == "REVERSIBLE" and p.impact.databases, "control: a capturable db"
    p = _predict(proj, "psql postgres://db.example.com/app -c 'DELETE FROM t'; rm a.txt")
    assert p.decision == "ESCALATE"


# ---- TODAY_MISS rows: today ALLOW, the shadow sees the change (each VERIFIED on the repo) ------

TODAY_MISS = [
    ("sqlite3 app.db < q.sql", "REVERSIBLE"),
    ("sqlite3 app.db \".read q.sql\"", "REVERSIBLE"),
    ("psql postgres://localhost/db -f q.sql", "REVERSIBLE"),
    ("mysql -h db.example.com app < q.sql", "ESCALATE"),
    ("sqlite3 app.db \".shell rm a.txt\"", "REVERSIBLE"),
    ("psql postgres://localhost/db -c '\\! rm a.txt'", "REVERSIBLE"),
    ("sqlite3 app.db \"SELECT writefile('a.txt', 'x')\"", "REVERSIBLE"),
    ("sqlite3 app.db \".output a.txt\" \"SELECT 1\"", "REVERSIBLE"),
    ("sqlite3 app.db \".open --new a.txt\"", "REVERSIBLE"),
    ("psql postgres://localhost/db -c \"SELECT 1\" -o a.txt", "REVERSIBLE"),
    ("psql postgres://localhost/db -c \"SELECT setval('s', 1)\"", "REVERSIBLE"),
    ("psql -h db.example.com -d app -c \"SELECT pg_terminate_backend(42)\"", "ESCALATE"),
    ("psql postgres://db.example.com/app -c \"GRANT ALL ON t TO public\"", "ESCALATE"),
    ("sqlite3 app.db \"PRAGMA journal_mode=DELETE\"", "REVERSIBLE"),
    ("psql postgres://db.example.com/app -c \"CALL purge()\"", "ESCALATE"),
    ("psql postgres://db.example.com/app -c \"COPY t FROM '/tmp/x.csv'\"", "ESCALATE"),
    ("mysql -h db.example.com -e \"LOAD DATA INFILE 'x' INTO TABLE t\" app", "ESCALATE"),
    # review C2a CR4 / CR5
    ("psql postgres://db.example.com/app -c 'SELECT purge_old_rows()'", "ESCALATE"),
    ("mysql -h db.example.com -e 'SET GLOBAL read_only = 0'", "ESCALATE"),
]


def _guard(proj, command):
    from demo_cli.guard import Guard, agent_directory
    with agent_directory(str(proj)):
        return Guard(config=Config(project_root=str(proj), mode="shadow")).evaluate(
            command, dialect="posix")


@pytest.mark.parametrize("command,shadow", TODAY_MISS, ids=[c for c, _ in TODAY_MISS])
def test_a_today_miss_row(proj, monkeypatch, command, shadow):
    import demo_cli.engine as engine
    monkeypatch.setattr(engine, "BUDGET_MS", SEMANTIC_BUDGET_MS)
    calm = _guard(proj, "sqlite3 app.db \"SELECT 1\"")
    assert (calm.decision.decision, calm.prediction["decision"]) == ("ALLOW", "ALLOW"), "control"
    r = _guard(proj, command)
    # The engine prediction correctly classifies the command as shadow
    assert r.prediction["decision"] == shadow


# ---- DIFFERENTIAL: the real sqlite3 --------------------------------------------------------------

SQLITE_CASES = [
    "sqlite3 app.db \"DELETE FROM t\"", "sqlite3 app.db \"SELECT * FROM t\"",
    "sqlite3 -readonly app.db \"DELETE FROM t\"", "sqlite3 \"file:app.db?mode=ro\" \"DELETE FROM t\"",
    "sqlite3 -deserialize app.db \"DELETE FROM t\"", "sqlite3 new.db \"SELECT 1\"",
    "sqlite3 new.db < /dev/null", "sqlite3 app.db < q.sql", "sqlite3 app.db < r.sql",
    "echo \"DELETE FROM t\" | sqlite3 app.db \"SELECT 1\"", "sqlite3 app.db \".shell rm a.txt\"",
    "sqlite3 -safe app.db \".shell rm a.txt\"", "sqlite3 app.db \"ATTACH 'o.db' AS o\"",
    "sqlite3 app.db \"SELECT writefile('w.txt', 'x')\"", "sqlite3 app.db \"VACUUM INTO 'copy.db'\"",
    "sqlite3 app.db \"VACUUM INTO 'a.txt'\"", "sqlite3 app.db \".open --new a.txt\"",
    "sqlite3 -lookaside 100 10 app.db \"DELETE FROM t\"", "sqlite3 app.db -readonly \"DELETE FROM t\"",
]


def _snapshot(root):
    out = {}
    for dp, _dn, fn in os.walk(str(root)):
        if ".demo_cli" in dp:
            continue
        for name in fn:
            p = os.path.join(dp, name)
            with open(p, "rb") as f:
                out[os.path.relpath(p, str(root))] = hashlib.sha256(f.read()).hexdigest()
    return out


@pytest.mark.skipif(shutil.which("sqlite3") is None, reason="sqlite3 is not installed here")
@pytest.mark.parametrize("command", SQLITE_CASES)
def test_the_prediction_covers_what_the_real_sqlite3_changes(proj, command):
    p = _predict(proj, command)
    predicted = {os.path.relpath(k, str(proj)) for k in list(p.impact.destroys) + list(p.impact.creates)}
    before = _snapshot(proj)
    subprocess.run(["bash", "-c", command], cwd=str(proj), capture_output=True, timeout=30)
    after = _snapshot(proj)
    changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
    assert changed <= predicted, f"changed but not predicted: {sorted(changed - predicted)}"
    if not predicted:
        assert not changed, "control: a prediction of nothing means nothing changed"


# ---- DIFFERENTIAL: a throwaway PostgreSQL (unix socket only) ------------------------------------

def _pg_bin():
    for base in sorted(os.listdir("/usr/lib/postgresql"), reverse=True) if os.path.isdir(
            "/usr/lib/postgresql") else []:
        d = os.path.join("/usr/lib/postgresql", base, "bin")
        if os.path.exists(os.path.join(d, "initdb")):
            return d
    return None


@pytest.fixture(scope="module")
def pg(tmp_path_factory):
    b = _pg_bin()
    if b is None or shutil.which("psql") is None:
        pytest.skip("no PostgreSQL server binaries here")
    root = tmp_path_factory.mktemp("pg")
    sock = root / "s"
    sock.mkdir()
    if len(str(sock)) + 16 > 100:
        pytest.skip("the socket path would be too long")
    subprocess.run([os.path.join(b, "initdb"), "-D", str(root / "data"), "-A", "trust", "-U", "t"],
                   check=True, capture_output=True, timeout=120)
    subprocess.run([os.path.join(b, "pg_ctl"), "-D", str(root / "data"), "-l", str(root / "log"),
                    "-o", f"-c listen_addresses='' -c unix_socket_directories={sock} -p 5432",
                    "-w", "start"], check=True, capture_output=True, timeout=120)
    yield f"postgresql:///postgres?host={sock}&port=5432&user=t"
    subprocess.run([os.path.join(b, "pg_ctl"), "-D", str(root / "data"), "-m", "fast", "stop"],
                   capture_output=True, timeout=120)


def _pg_state(url):
    q = ("SELECT string_agg(tablename || ':' || (xpath('/row/c/text()', query_to_xml("
         "'select count(*) as c from ' || quote_ident(tablename), false, true, '')))[1]::text, ',' "
         "ORDER BY tablename) FROM pg_tables WHERE schemaname = 'public'")
    return subprocess.run(["psql", url, "-X", "-A", "-t", "-c", q], capture_output=True,
                          text=True, timeout=30).stdout.strip()


PG_CASES = [
    "DELETE FROM t", "SELECT 1", "EXPLAIN DELETE FROM t", "EXPLAIN ANALYZE DELETE FROM t",
    "WITH d AS (DELETE FROM t RETURNING *) SELECT count(*) FROM d", "SELECT * INTO t2 FROM t",
    "BEGIN; DELETE FROM t; ROLLBACK;",
]


@pytest.mark.parametrize("sql", PG_CASES)
def test_the_prediction_covers_what_real_postgres_changes(proj, pg, sql):
    subprocess.run(["psql", pg, "-X", "-q", "-c",
                    "DROP TABLE IF EXISTS t, t2; CREATE TABLE t(a int); INSERT INTO t VALUES (1),(2)"],
                   check=True, capture_output=True, timeout=30)
    command = f"psql '{pg}' -X -c \"{sql}\""
    p = _predict(proj, command)
    before = _pg_state(pg)
    assert before == "t:2", "control: the fixture holds 2 rows"
    subprocess.run(["bash", "-c", command], capture_output=True, timeout=30)
    changed = _pg_state(pg) != before
    predicted = bool(p.impact.databases)
    assert predicted or not changed, f"the database changed but nothing was predicted: {sql}"
    if sql.startswith("BEGIN"):
        assert predicted and not changed, "the disclosed over-prediction (Q13)"


# ---- grammars, against the installed tools ------------------------------------------------------

@pytest.mark.skipif(shutil.which("sqlite3") is None, reason="sqlite3 is not installed here")
def test_the_sqlite3_grammar_matches_its_help():
    from demo_cli.engine.rules_sql import SQLITE3_OPTIONS
    text = subprocess.run(["sqlite3", "-help"], capture_output=True, text=True).stderr + \
        subprocess.run(["sqlite3", "-help"], capture_output=True, text=True).stdout
    rows = re.findall(r"^\s+(-[a-zA-Z][\w-]*)((?: [A-Z][A-Z.]*)*)\s{2,}", text, re.M)
    assert len(rows) > 20, "control: the help was read"
    for opt, args in rows:
        n = len(args.split())
        if opt.startswith("-[no]"):
            continue
        if n == 0:
            assert opt in SQLITE3_OPTIONS.flags, opt
        else:
            assert opt in SQLITE3_OPTIONS.values, opt
            canon = SQLITE3_OPTIONS.values[opt]
            if n > 1 and "..." not in args:
                assert SQLITE3_OPTIONS.arity.get(canon, 1) == n, opt


@pytest.mark.skipif(shutil.which("psql") is None, reason="psql is not installed here")
def test_the_psql_grammar_matches_its_help():
    from demo_cli.engine.rules_sql import PSQL_OPTIONS
    text = subprocess.run(["psql", "--help"], capture_output=True, text=True).stdout
    required = set(re.findall(r"(--[a-z][\w-]*)=[A-Z]", text))
    shorts = set(re.findall(r"^\s+(-[\w?]),", text, re.M))
    assert len(required) > 5 and len(shorts) > 10, "control: the help was read"
    assert not sorted(o for o in required if o not in PSQL_OPTIONS.values)
    assert not sorted(s for s in shorts if s not in PSQL_OPTIONS.values and s not in PSQL_OPTIONS.flags)


def test_mysql_is_marked_unverified():
    from demo_cli.engine.rules_sql import MYSQL_OPTIONS
    from demo_cli.engine.rules import all_rules
    assert {r.id for r in all_rules() if not r.verified} - \
        {"prettier", "eslint", "black", "isort", "rustfmt", "rsync"} == {"mysql"}
    assert MYSQL_OPTIONS.attached == {"-p": "password"}, "-p takes a password glued on only"


# ---- perf: the SQL modules are loaded only when SQL is met --------------------------------------

def test_the_sql_modules_load_only_when_a_sql_client_or_line_is_met(tmp_path):
    import sys
    code = (
        "import os, sys\n"
        "from demo_cli.config import Config\n"
        "from demo_cli.engine import predict\n"
        "cfg = Config(project_root=os.getcwd())\n"
        "for c in ('rm a.txt', 'cp a.txt b.txt', 'echo x > a.txt', 'ls -la'):\n"
        "    predict(c, cfg, budget_ms=10000)\n"
        "sql = lambda: sorted(m for m in sys.modules if m.split('.')[-1] in ('sql', 'sqlclients', 'rules_sql'))\n"
        "print('before', sql())\n"
        "predict('sqlite3 app.db \"SELECT 1\"', cfg, budget_ms=10000)\n"
        "print('after', sql())\n")
    (tmp_path / "a.txt").write_text("a")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    out = subprocess.run([sys.executable, "-c", code], cwd=str(tmp_path), env=env,
                         capture_output=True, text=True, timeout=60).stdout
    assert ("after ['demo_cli.engine.rules_sql', 'demo_cli.engine.sql', "
            "'demo_cli.engine.sqlclients']") in out, \
        "control: a SQL client loads them"
    assert "before []" in out


# ---- review C2a (2026-09-28): CR1-CR5 --------------------------------------------------------

def _names(paths, root):
    return {os.path.relpath(p, str(root)) + ("/" if os.path.isdir(p) else "") for p in paths}


def test_cr1_without_a_target_a_sql_line_is_read_as_shell_too(proj):
    (proj / "dir").mkdir()
    p = _predict(proj, "DELETE FROM t")
    assert p.impact.no_capture == {"db:(unnamed)": "SQL with no database named (--db / --db-url)"}, \
        "control: SQL alone still reaches db:(unnamed)"
    p = _predict(proj, "SELECT 1; rm -rf dir")
    assert _names(p.impact.destroys, proj) == {"dir/"} and not p.impact.no_capture, \
        "bash runs rm after `SELECT: command not found`; SELECT writes nothing"
    p = _predict(proj, "DELETE FROM t; rm a.txt")
    assert _names(p.impact.destroys, proj) == {"a.txt"} and "db:(unnamed)" in p.impact.no_capture
    # && : SELECT fails in bash, so rm does not run there. The simulation does not know an
    # unknown command fails, so it keeps both branches (may-semantics): a.txt MAY be destroyed.
    assert _names(_predict(proj, "SELECT 1 && rm a.txt").impact.destroys, proj) == {"a.txt"}
    assert not {"SELECT", "DELETE"} & set(p.impact.uncovered), "not reported as unknown tools"


def test_cr1_with_a_target_the_line_is_sql_only(proj):
    p = _predict(proj, "DELETE FROM t WHERE id < 10", explicit_db="app.db")
    assert _names(p.impact.destroys, proj) == {"app.db"}, "`< 10` is SQL, not a redirection"


@pytest.mark.parametrize("command", [
    "psql -h localhost postgres://db.example.com/app -c 'DELETE FROM t'",
    "psql postgres://db.example.com/app -h localhost -c 'DELETE FROM t'",
    "psql -d postgres://db.example.com/app -h localhost -c 'DELETE FROM t'",
    "psql 'host=db.example.com dbname=app' -h localhost -c 'DELETE FROM t'",
])
def test_cr2_the_connection_strings_host_beats_h(proj, command):
    """VERIFIED on psql 18.4 (loopback hosts, nothing listening): the URL or
    conninfo host is the one connected to, whatever -h says."""
    assert _predict(proj, "psql -h db.example.com -d app -c 'DELETE FROM t'").impact.remote, \
        "control: -h alone names the host"
    p = _predict(proj, command)
    assert p.impact.remote == {"db:db.example.com/app": "DELETE"} and not p.impact.databases
    assert p.decision == "ESCALATE"


def test_cr2_database_name_precedence(proj):
    """VERIFIED (throwaway cluster): -d URL wins over a positional name (then a
    user name); with -d, a positional URL is ignored; PGDATABASE is lowest."""
    assert "db:db.example.com/a" in _predict(
        proj, "psql -d postgres://db.example.com/a b -c 'DELETE FROM t'").impact.remote
    assert "db:db.example.com/b" in _predict(
        proj, "PGDATABASE=c psql -h db.example.com -d b -c 'DELETE FROM t'").impact.remote
    assert "db:db.example.com/c" in _predict(
        proj, "PGDATABASE=c psql -h db.example.com -c 'DELETE FROM t'").impact.remote


def test_cr3_imports_are_outside_the_budget(proj, monkeypatch):
    """Deterministic: a clock that only moves while a family is imported."""
    import demo_cli.engine.rules as rules_mod
    import demo_cli.engine.simulate as simulate

    class Clock:
        t = 0.0

        def perf_counter(self):
            return self.t

        # B0 (msg 037): the budget now reads the CPU clock too.
        def process_time(self):
            return self.t
    clock = Clock()
    real = rules_mod.family_rules

    def slow_import(module):
        clock.t += 3600.0                                  # an import that takes an hour
        return real(module)
    monkeypatch.setattr(simulate, "time", clock)
    monkeypatch.setattr(simulate, "family_rules", slow_import)
    p = _predict(proj, "sqlite3 app.db 'DELETE FROM t'")    # preload: before the clock starts
    assert p.decision == "REVERSIBLE"
    w = simulate.World(simulate.RULES, simulate.Budget(10.0))
    rules = w.load_family("psql")                           # mid-analysis: untimed
    assert rules and w.budget.deadline > 3600.0
    w.budget.check()


@pytest.mark.parametrize("query", [
    "SELECT count(*), max(a), lower(b) FROM t WHERE c IN (1, 2) GROUP BY d",
    "SELECT now(), date_trunc('day', ts), coalesce(x, 0) FROM t",
    "SELECT json_build_object('a', a) FROM t WHERE EXISTS (SELECT 1 FROM u)",
    "SELECT a FROM t JOIN u USING (id) ORDER BY row_number() OVER (PARTITION BY b)",
    "SELECT pg_size_pretty(pg_database_size(current_database()))",
    "SELECT pg_catalog.lower('X')",
    "SELECT 'purge_old_rows()' AS literal_text",
    "SELECT * FROM generate_series(1, 3)",
])
def test_cr4_common_reads_stay_read(query):
    assert classify(query, "postgres").kind == READ


@pytest.mark.parametrize("query", ["SELECT purge_old_rows()", "SELECT public.cleanup(3)",
                                   "SELECT a, archive_and_delete(id) FROM t"])
def test_cr4_a_select_calling_an_unknown_function_is_a_may_write(query):
    assert classify("SELECT count(*) FROM t", "postgres").kind == READ, "control"
    assert classify(query, "postgres").kind == UNKNOWN
    assert classify(query, "mysql").kind == UNKNOWN
    assert classify(query, "sqlite").kind == READ, "sqlite's CLI cannot define functions"


@pytest.mark.parametrize("stmt,kind", [
    ("SET GLOBAL read_only = 0", WRITE), ("SET PERSIST max_connections = 1", WRITE),
    ("SET PERSIST_ONLY x = 1", WRITE), ("SET @@global.read_only = 0", WRITE),
    ("SET PASSWORD FOR bob = 'x'", WRITE), ("SET SESSION sql_mode = ''", READ),
    ("SET @v = 1", READ), ("START TRANSACTION", READ), ("START REPLICA", UNKNOWN),
])
def test_cr5_mysql_server_wide_set_and_start(stmt, kind):
    assert classify(stmt, "mysql").kind == kind
    assert classify("SET search_path = x", "postgres").kind == READ, "control: pg SET is session"


@pytest.mark.parametrize("query", [
    "WITH d(x) AS (SELECT 1) SELECT x FROM d",
    "SELECT n FROM generate_series(1, 3) AS g(n)",
    "WITH a AS (SELECT 1), b(y) AS (SELECT 2) SELECT * FROM b",
    "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT * FROM r",
    "WITH m(x) AS MATERIALIZED (SELECT 1) SELECT x FROM m",
])
def test_cr6_column_lists_are_not_calls(query):
    """review C2a round 1, CR6 (VERIFIED on the round-1 tree: ESCALATE on remote pg)."""
    assert classify(query, "postgres").kind == READ


@pytest.mark.parametrize("query", ["SELECT d(1)", "WITH d AS (SELECT purge()) SELECT 1",
                                   "SELECT a, purge(x) AS y FROM t"])
def test_cr6_real_calls_stay_unknown(query):
    assert classify(query, "postgres").kind == UNKNOWN
