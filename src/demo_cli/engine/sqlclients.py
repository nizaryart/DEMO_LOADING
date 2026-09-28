"""SQL clients - sqlite3, psql, mysql/mariadb - and bare SQL lines (Part C2a).

What each client runs, against what, and what that does to the world.

SOURCES, in the order each client runs them:
  sqlite3  -init FILE, every -cmd, then the SQL operands after FILENAME; with
           a SQL operand STDIN IS NOT READ (VERIFIED, sqlite3 3.46.1).
  psql     every -c / -f in order; with either, stdin is not read (VERIFIED
           for -c, psql 18.4).
  mysql    -e, else stdin (UNVERIFIED: mysql is not installed here).
  stdin    a here-doc, a here-string, `< file`, or the pipe from echo /
           printf / cat. Files are read THROUGH THE OVERLAY (review C2, R4):
           content written earlier on the line is unknown.

TARGETS. A sqlite database is a FILE: a write edits it (captured as a file;
REVERSIBLE in the project). postgres/mysql targets are labelled from host
and database names ONLY (review C2, R2) - never userinfo or query strings:
  remote host                          -> REMOTE db:<host>/<name>
  postgres, a literal local URL         -> capturable (today's pg_dump path)
  anything else (no URL, mysql, a host  -> no capture path -> ESCALATE
  from a service or config file)           (review C2, Q4)

A statement we cannot classify, or SQL we cannot read, is a MAY-write to its
target (it counts as one) and is reported as not understood: a client can
also shell out (.shell, \\!, system).
"""
from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .effects import CREATE, DELETE, OVERWRITE, _LOSS_ORDER
from .sql import META, READ, UNKNOWN, WRITE, statements

# R4: the largest SQL text read from a file or stdin. MEASURED 2026-09-28
# (SP/sql_timing.py, three script shapes): 256 KiB takes 21-31 ms, over the
# whole 10 ms budget; 64 KiB 4.6-7.0 ms; 32 KiB 2.0-3.5 ms. Larger text is
# UNKNOWN (and a may-write), never a guess.
MAX_SQL_BYTES = 32 * 1024
MAX_INCLUDE_DEPTH = 4
_LOCAL_HOSTS = ("", "localhost", "127.0.0.1", "::1")
_DIALECT = {"sqlite3": "sqlite", "psql": "postgres", "mysql": "mysql", "mariadb": "mysql"}


def _worse(a: Optional[str], b: str) -> str:
    return b if a is None or _LOSS_ORDER.index(b) < _LOSS_ORDER.index(a) else a


class DbTarget:
    """A postgres / mysql database: `label` is db:<host>/<name>."""
    __slots__ = ("label", "remote", "capturable", "why")

    def __init__(self, host: Optional[str], name: Optional[str], literal_url: bool,
                 dialect: str, host_unknown: str = ""):
        h = (host or "").lower()
        self.label = f"db:{h or '(default)'}/{name or '(default)'}"
        local = not host_unknown and (h in _LOCAL_HOSTS or h.startswith("/"))
        self.remote = not host_unknown and not local
        self.capturable = dialect == "postgres" and literal_url and local
        self.why = (host_unknown or ("demo_cli has no MySQL capture" if dialect == "mysql"
                                     else "no connection URL to capture (pg_dump needs one)"))


def pg_target(url_or_conn: Optional[str], host: Optional[str], name: Optional[str],
              prefix_env: Dict[str, str]) -> DbTarget:
    """From a URL / conninfo / dbname plus -h and the line's PG* assignments.
    VERIFIED precedence (psql 18.4; loopback hosts and a throwaway cluster,
    review C2a CR2): a connection string's own host and dbname beat -h / -d;
    -h beats PGHOST; PGDATABASE is lowest. A URL may carry its host in
    ?host=."""
    literal_url = False
    unknown = ""
    if url_or_conn:
        v = url_or_conn
        if "://" in v:
            u = urlsplit(v)
            literal_url = u.scheme.lower() in ("postgres", "postgresql")
            qhost = next((val for key, val in (kv.partition("=")[::2] for kv in
                                                u.query.split("&")) if key == "host"), None)
            host = u.hostname or qhost or host
            name = (u.path.lstrip("/") or None) or name
        elif "=" in v:
            kv = dict((k.lower(), val.strip("'")) for k, val in
                      re.findall(r"(\w+)\s*=\s*('(?:[^']|\\')*'|\S+)", v))
            host = kv.get("host") or kv.get("hostaddr") or host
            name = kv.get("dbname") or name
            if kv.get("service") and not kv.get("host") and not kv.get("hostaddr"):
                unknown = "the host comes from a pg_service entry"
        else:
            name = v
    host = host or prefix_env.get("PGHOST") or prefix_env.get("PGHOSTADDR")
    name = name or prefix_env.get("PGDATABASE")
    if prefix_env.get("PGSERVICE") and not host:
        unknown = "the host comes from a pg_service entry"
    return DbTarget(host, name, literal_url, "postgres", unknown)


class Session:
    """One client run: its targets and what its statements do to them."""

    def __init__(self, w, inv, state, dialect: str, readonly: bool = False,
                 safe: bool = False):
        self.w, self.inv, self.state, self.dialect = w, inv, state, dialect
        self.readonly, self.safe = readonly, safe
        self.sqlite: Optional[str] = None           # the main sqlite file (None: memory)
        self.attached: List[str] = []
        self.db: Optional[DbTarget] = None
        self.dbs: Dict[str, Tuple[DbTarget, Optional[str]]] = {}
        self.kind: Optional[str] = None             # the worst write on the sqlite files
        self.ran = False                            # a SQL statement executed
        self.keep = None                            # a filter on statements (dual reading)

    # ---- targets -------------------------------------------------------------
    def use_db(self, t: DbTarget) -> None:
        self.db = t
        self.dbs.setdefault(t.label, (t, None))

    def _path(self, arg: str) -> Optional[str]:
        if os.path.isabs(arg):
            return os.path.normpath(arg)
        if self.state.cwd is None:
            self.w.impact.not_understood(self.inv.text, "the working directory is unknown")
            return None
        return os.path.normpath(os.path.join(self.state.cwd, arg))

    # ---- statements -----------------------------------------------------------
    def write(self, kind: str) -> None:
        if self.db is not None:
            t, old = self.dbs[self.db.label]
            self.dbs[self.db.label] = (t, _worse(old, kind))
        else:
            self.kind = _worse(self.kind, kind)

    def unknown(self, why: str) -> None:
        self.w.impact.not_understood(self.inv.text, why)
        self.write(DELETE)                                    # may-semantics

    def run_text(self, text: str, depth: int = 0) -> None:
        for piece, st in statements(text, self.dialect, self.w.budget):
            if self.keep is not None and not self.keep(piece):
                continue
            if st is None:
                self.meta(piece, depth)
                continue
            self.ran = True
            if st.kind == WRITE:
                if st.words[:1] == ["ATTACH"] and self.dialect == "sqlite":
                    self.attach(st)
                    continue
                if (st.words[:1] == ["VACUUM"] and st.literals
                        and self.dialect == "sqlite"):
                    self.vacuum_into(self._path(st.literals[-1]))
                    continue
                if "writefile" in (w.lower() for w in st.words) and self.dialect == "sqlite":
                    self.writefile(st)
                    continue
                self.write(st.effect or OVERWRITE)
            elif st.kind == UNKNOWN:
                self.unknown(f"SQL not understood: {st.why}")

    def run_file(self, path: Optional[str], depth: int) -> None:
        if path is None:
            return
        if depth >= MAX_INCLUDE_DEPTH:
            self.unknown("SQL files include each other too deeply")
            return
        if not self.w.node(self.state, path).exists:
            return                                   # the client reports it; nothing runs
        text, why = self.w.read_text(self.state, path, MAX_SQL_BYTES)
        if text is None:
            self.unknown(f"the SQL it runs is unknown: {why}")
            return
        self.run_text(text, depth + 1)

    def attach(self, st) -> None:
        m = re.match(r"(?is)\s*ATTACH\s+(?:DATABASE\s+)?(.*?)\s+AS\s+", st.text)
        expr = m.group(1).strip() if m else ""
        lit = st.literals[0] if re.fullmatch(r"'(?:[^']|'')*'", expr) else None
        if lit is None:
            self.unknown("ATTACH of a database named by an expression")
            return
        if lit in ("", ":memory:") or lit.startswith("file::memory:"):
            return
        if self.safe:
            return                                            # -safe refuses ATTACH (VERIFIED)
        p = self._path(lit[5:] if lit.startswith("file:") else lit)
        if p:
            self.attached.append(p)

    def vacuum_into(self, p: Optional[str]) -> None:
        """VERIFIED (3.46.1): VACUUM INTO fails on an existing non-empty file
        ("file is not a database") and writes an absent or empty one."""
        if p is None:
            return
        n = self.w.node(self.state, p)
        if n.exists and n.origins == frozenset({p}):
            try:
                if os.path.getsize(p) > 0:
                    return
            except OSError:
                pass
        self.w.write(self.state, p, False)

    def writefile(self, st) -> None:
        lit = st.literals[0] if st.literals else None
        p = self._path(lit) if lit else None
        if p is None:
            self.unknown("writefile() to a path we cannot read")
            return
        self.w.write(self.state, p, False)

    def nested(self, command: str) -> None:
        from ..model import parse
        if self.safe:
            return                                            # -safe refuses .shell (VERIFIED)
        self.w.subshell(parse(command), self.state, 1)

    def local_write(self, arg: str, appending: bool = False) -> None:
        arg = arg.strip().strip("'\"")
        if not arg or arg in ("stdout", "-"):
            return
        if arg.startswith("|"):
            self.nested(arg[1:].strip())
            return
        p = self._path(arg)
        if p:
            self.w.write(self.state, p, appending)

    # ---- client commands --------------------------------------------------------
    def meta(self, line: str, depth: int) -> None:
        if self.dialect == "sqlite":
            return self.sqlite_meta(line, depth)
        if self.dialect == "postgres":
            return self.psql_meta(line, depth)
        return self.mysql_meta(line, depth)

    def sqlite_meta(self, line: str, depth: int) -> None:
        cmd, _, arg = line.partition(" ")
        cmd, arg = cmd.lower(), arg.strip()
        if cmd in (".shell", ".system"):
            self.nested(arg)
        elif cmd == ".read":
            if arg.startswith("|"):
                self.nested(arg[1:])
                self.unknown(".read | runs a command's output as SQL")
            else:
                self.run_file(self._path(arg.strip("'\"")), depth)
        elif cmd in (".output", ".once", ".log", ".trace", ".testcase"):
            if cmd == ".once" and arg.startswith(("-x", "-e")):
                return
            self.local_write(arg)
        elif cmd in (".save", ".backup"):
            parts = arg.split()
            if parts:
                self.local_write(parts[-1])
        elif cmd == ".restore":
            self.ran = True
            self.write(DELETE)                                # the main db is replaced
        elif cmd == ".open":
            parts = arg.split()
            new = "--new" in parts
            names = [x for x in parts if not x.startswith("-")]
            if names:
                p = self._path(names[-1].strip("'\""))
                if p and new and self.w.node(self.state, p).exists:
                    self.w.replace(self.state, p, OVERWRITE)  # VERIFIED: --new empties it
                self.sqlite = p
        elif cmd == ".import":
            self.ran = True
            self.write(OVERWRITE)
        elif cmd == ".clone":
            parts = arg.split()
            if parts:
                self.local_write(parts[0])
        elif cmd in (".load", ".archive", ".ar", ".cd", ".edit", ".excel", ".recover",
                     ".filectrl", ".dbconfig", ".selftest"):
            if cmd in (".recover",):
                return
            self.unknown(f"sqlite3 {cmd} is not modelled")
        elif cmd in _SQLITE_INERT:
            return
        else:
            self.unknown(f"sqlite3 {cmd} is not modelled")

    def psql_meta(self, line: str, depth: int) -> None:
        m = re.match(r"\\(\S+)\s*(.*)", line, re.S)
        if not m:
            return
        cmd, arg = m.group(1), m.group(2).strip()
        if cmd == "!":
            if arg:
                self.nested(arg)
        elif cmd in ("i", "ir", "include", "include_relative"):
            self.run_file(self._path(arg.strip("'\"")), depth)
        elif cmd in ("o", "out", "w", "write", "s"):
            if arg:
                self.local_write(arg)
        elif cmd in ("g", "gx"):
            if arg:
                self.local_write(arg)
        elif cmd == "copy":
            self.psql_copy(arg)
        elif cmd == "gexec":
            self.unknown("\\gexec runs a query's results as SQL")
        elif cmd in ("c", "connect"):
            self.connect(arg)
        elif cmd in ("lo_unlink", "lo_import"):
            self.ran = True
            self.write(OVERWRITE)
        elif cmd == "lo_export":
            parts = arg.split()
            if len(parts) > 1:
                self.local_write(parts[1])
        elif cmd in ("e", "edit", "ef", "ev", "cd", "setenv", "prompt"):
            self.unknown(f"psql \\{cmd} is not modelled")
        elif cmd in _PSQL_INERT or cmd.startswith("d") or cmd.startswith("l"):
            return
        else:
            self.unknown(f"psql \\{cmd} is not modelled")

    def psql_copy(self, arg: str) -> None:
        m = re.search(r"\b(TO|FROM)\s+(PROGRAM\s+)?('(?:[^']|'')*'|\S+)", arg, re.I)
        if not m:
            self.unknown("\\copy not understood")
            return
        where = m.group(3).strip("'")
        if m.group(1).upper() == "FROM":
            self.ran = True
            self.write(OVERWRITE)
            if m.group(2):
                self.nested(where)
        elif m.group(2):
            self.nested(where)
        elif where.lower() not in ("stdout", "pstdout"):
            self.local_write(where)

    def connect(self, arg: str) -> None:
        parts = arg.split()
        if not parts or parts[0] == "-":
            return
        if "://" in parts[0] or "=" in parts[0]:
            self.use_db(pg_target(parts[0], None, None, {}))
            return
        host = parts[2] if len(parts) > 2 and parts[2] != "-" else None
        self.use_db(pg_target(None, host or None, parts[0], {}))

    def mysql_meta(self, line: str, depth: int) -> None:
        word, _, arg = line.partition(" ")
        cmd = word.lower().lstrip("\\")
        arg = arg.strip()
        if word.startswith("\\") and len(word) >= 2:
            cmd = {"!": "system", ".": "source", "T": "tee", "u": "use", "r": "connect",
                   "d": "delimiter", "e": "edit"}.get(word[1:2], cmd)
            if not arg:
                arg = word[2:].strip()
        if cmd == "system":
            self.nested(arg)
        elif cmd == "source":
            self.run_file(self._path(arg.strip("'\"")), depth)
        elif cmd == "tee":
            self.local_write(arg, appending=True)
        elif cmd == "use":
            if self.db is not None:
                host = self.db.label[3:].split("/")[0]
                self.use_db(DbTarget(None if host == "(default)" else host,
                                     arg.strip("`;"), False, "mysql"))
        elif cmd == "connect":
            self.unknown("mysql connect switches the server")
        elif cmd in ("pager", "edit"):
            self.unknown(f"mysql {cmd} is not modelled")
        return

    # ---- the end: effects on the targets -------------------------------------------
    def finish(self) -> None:
        w, state = self.w, self.state
        if not self.readonly:
            files = ([self.sqlite] if self.sqlite else []) + self.attached
            for p in files:
                n = w.node(state, p)
                if self.kind is not None:
                    if n.exists:
                        if not n.is_dir:
                            w.replace(state, p, OVERWRITE)
                            for side in ("-wal", "-shm", "-journal"):
                                if w.node(state, p + side).exists:
                                    w.replace(state, p + side, OVERWRITE)
                    else:
                        w.write(state, p, False)
                elif (self.ran or p in self.attached) and not n.exists:
                    w.write(state, p, False)          # VERIFIED: opened = created, even empty
        for t, kind in self.dbs.values():
            if kind is None or self.readonly:
                continue
            if t.remote:
                w.impact.reach(t.label, DELETE if kind == DELETE else
                               OVERWRITE if kind != CREATE else CREATE)
            elif t.capturable:
                old = w.impact.databases.get(t.label)
                w.impact.databases[t.label] = _worse(old, kind)
            else:
                w.impact.no_capture.setdefault(t.label, t.why)


_SQLITE_INERT = {".dump", ".schema", ".tables", ".indexes", ".indices", ".mode", ".headers",
                 ".header", ".separator", ".width", ".nullvalue", ".print", ".show", ".stats",
                 ".timer", ".echo", ".bail", ".changes", ".eqp", ".explain", ".help",
                 ".databases", ".dbinfo", ".fullschema", ".lint", ".parameter", ".prompt",
                 ".quit", ".exit", ".sha3sum", ".timeout", ".limit", ".scanstats",
                 ".connection", ".vfsinfo", ".vfslist", ".vfsname", ".crnl", ".binary",
                 ".imposter", ".expert", ".unmodule", ".auth"}
_PSQL_INERT = {"set", "unset", "echo", "qecho", "warn", "pset", "a", "t", "x", "timing",
               "conninfo", "encoding", "q", "quit", "?", "h", "help", "if", "elif", "else",
               "endif", "f", "C", "H", "T", "z", "sf", "sv", "watch", "bind", "parse",
               "bind_named", "close_prepared", "errverbose", "getenv", "gdesc", "gset",
               "restrict", "unrestrict", "p", "print", "r", "reset", "copyright", "startpipeline",
               "endpipeline", "syncpipeline", "sendpipeline", "flush", "flushrequest",
               "getresults"}


# ---- stdin -----------------------------------------------------------------------------

def stdin_source(w, inv, state) -> Tuple[str, object]:
    """("text", str) | ("files", [path]) | ("unknown", why) | ("none", None)."""
    found: Tuple[str, object] = ("none", None)
    for r in inv.redirects:
        if r.fd not in (None, "0"):
            continue
        if r.op == "<" and r.target is not None:
            if r.target.expands:
                found = ("unknown", "stdin comes from a file named by an expansion")
            else:
                found = ("files", w.paths([r.target], state, inv))
        elif r.op in ("<<", "<<-") and r.heredoc is not None:
            body = r.heredoc.body
            if not r.heredoc.quoted and ("$" in body or "`" in body):
                found = ("unknown", "the shell expands the here-doc before the client reads it")
            else:
                found = ("text", body)
        elif r.op == "<<<" and r.target is not None:
            found = (("unknown", "a here-string built from an expansion") if r.target.expands
                     else ("text", r.target.value + "\n"))
    if found[0] != "none":
        return found
    up = w.upstream
    if up is None or not up.argv:
        return found
    tool = os.path.basename(up.argv[0].value)
    args = up.argv[1:]
    if any(a.expands for a in up.argv):
        return ("unknown", f"stdin comes from {tool} with an expansion")
    if tool == "echo":
        interp = False
        while args and re.fullmatch(r"-[neE]+", args[0].value):
            interp = interp or "e" in args[0].value
            args = args[1:]
        text = " ".join(a.value for a in args) + "\n"
        return ("text", text.replace("\\n", "\n") if interp else text)
    if tool == "printf" and args:
        fmt = args[0].value
        if "%" in fmt.replace("%%", ""):
            return ("unknown", "stdin comes from a printf format")
        return ("text", fmt.replace("\\n", "\n").replace("%%", "%"))
    if tool == "cat":
        names = [a for a in args if not a.value.startswith("-")]
        return ("files", w.paths(names, state, inv)) if names else ("unknown", "cat reads stdin")
    return ("unknown", f"stdin comes from {tool}")


def feed_stdin(sess: Session, w, inv, state, depth: int = 0) -> None:
    kind, what = stdin_source(w, inv, state)
    if kind == "text":
        if len(what) > MAX_SQL_BYTES:
            sess.unknown("the SQL on stdin is too large to read")
        else:
            sess.run_text(what, depth)
    elif kind == "files":
        for p in what:
            sess.run_file(p, depth)
    elif kind == "unknown":
        sess.unknown(f"the SQL it runs is unknown: {what}")


def _ordered(parsed, *names) -> List[Tuple[str, object]]:
    items = [(w.start, name, w) for name in names for w in parsed.options.get(name, [])]
    return [(name, w) for _s, name, w in sorted(items, key=lambda x: x[0])]


def _prefix_env(inv) -> Dict[str, str]:
    env = {}
    for wd in inv.prefix:
        name, _eq, value = wd.value.partition("=")
        if not wd.expands:
            env[name] = value
    return env


# ---- the three clients -------------------------------------------------------------

def _input_fails(w, inv, state) -> bool:
    """`< missing`: the shell cannot open it, and the client never starts."""
    for r in inv.redirects:
        if r.op == "<" and r.fd in (None, "0") and r.target is not None and not r.target.expands:
            for p in w.paths([r.target], state, inv):
                if not w.node(state, p).exists:
                    return True
    return False


def sql_client(w, inv, parsed, state, tool) -> None:
    dialect = _DIALECT[tool]
    f = parsed.flags
    if f & {"help", "version", "list"} or _input_fails(w, inv, state):
        return
    if dialect == "sqlite":
        return _sqlite3(w, inv, parsed, state)
    if dialect == "postgres":
        return _psql(w, inv, parsed, state)
    return _mysql(w, inv, parsed, state)


def _sqlite3(w, inv, parsed, state) -> None:
    f, o = parsed.flags, parsed.options
    if "archive" in o or "zip" in f:
        w.impact.not_understood(inv.text, "sqlite3 archive mode (-A / -zip) is not modelled")
        return
    ops = parsed.operands
    readonly = bool(f & {"readonly", "deserialize"})
    sess = Session(w, inv, state, "sqlite", readonly=readonly, safe="safe" in f)
    if ops:
        name = ops[0]
        if name.expands:
            w.impact.not_understood(inv.text, "the database is named by an expansion")
            sess.write(DELETE)
        else:
            v = name.value
            if v.startswith("file:"):
                base, _q, query = v[5:].partition("?")
                if "mode=ro" in query or "immutable=1" in query:
                    sess.readonly = True
                if "mode=memory" not in query and base not in ("", ":memory:"):
                    sess.sqlite = sess._path(base)
            elif v not in ("", ":memory:"):
                sess.sqlite = sess._path(v)
    for p in w.paths(o.get("init", []), state, inv):
        sess.run_file(p, 0)
    for c in o.get("cmd", []):
        if c.expands:
            sess.unknown("a -cmd built from an expansion")
        else:
            sess.run_text(c.value, 0)
    sql_args = ops[1:]
    for a in sql_args:
        if a.expands:
            sess.unknown("SQL built from an expansion")
        else:
            sess.run_text(a.value, 0)
    if not sql_args:
        feed_stdin(sess, w, inv, state)
    sess.finish()


def _psql(w, inv, parsed, state) -> None:
    o = parsed.options
    ops = parsed.operands
    env = _prefix_env(inv)
    conn = o.get("dbname", [None])[-1]
    conn_v = None
    if conn is not None:
        conn_v = conn.value if not conn.expands else None
    elif ops:
        conn_v = ops[0].value if not ops[0].expands else None
    host = o.get("host", [None])[-1]
    host_v = host.value if host is not None and not host.expands else None
    expands = (conn is not None and conn.expands) or (ops and ops[0].expands and conn is None) \
        or (host is not None and host.expands)
    sess = Session(w, inv, state, "postgres")
    if expands:
        w.impact.not_understood(inv.text, "the connection is named by an expansion")
        sess.use_db(DbTarget(None, None, False, "postgres",
                             "the connection is named by an expansion"))
    elif conn_v is None and host_v is None and w.sql_target[1] and not env:
        sess.use_db(pg_target(w.sql_target[1], None, None, {}))      # the check door's --db-url
    else:
        sess.use_db(pg_target(conn_v, host_v, None, env))
    run = _ordered(parsed, "command", "file")
    for name, word in run:
        if word.expands:
            sess.unknown(f"a -{'c' if name == 'command' else 'f'} built from an expansion")
        elif name == "command":
            sess.run_text(word.value, 0)
        else:
            if word.value == "-":
                feed_stdin(sess, w, inv, state)
            else:
                for p in w.paths([word], state, inv):
                    sess.run_file(p, 0)
    for name in ("output", "log_file"):
        for word in o.get(name, []):
            if not word.expands:
                sess.local_write(word.value, appending=name == "log_file")
    if not run:
        feed_stdin(sess, w, inv, state)
    sess.finish()


def _mysql(w, inv, parsed, state) -> None:
    o, ops = parsed.options, parsed.operands
    host = o.get("host", [None])[-1]
    db = o.get("database", [None])[-1]
    name = db.value if db is not None and not db.expands else (
        ops[0].value if ops and not ops[0].expands else None)
    unknown = ""
    if o.get("defaults_file") or o.get("defaults_extra_file") or o.get("login_path"):
        unknown = "the host comes from a MySQL option file"
    if host is not None and host.expands:
        unknown = "the host is named by an expansion"
    sess = Session(w, inv, state, "mysql")
    sess.use_db(DbTarget(host.value if host is not None and not host.expands else None,
                         name, False, "mysql", unknown))
    execs = o.get("execute", [])
    for word in execs:
        if word.expands:
            sess.unknown("SQL built from an expansion")
        else:
            sess.run_text(word.value, 0)
    for word in o.get("tee", []):
        if not word.expands:
            sess.local_write(word.value, appending=True)
    if not execs:
        feed_stdin(sess, w, inv, state)
    sess.finish()


# ---- a bare SQL line (the check door; review C2, Q3) -------------------------------------

def run_bare_sql(w, command: str, state, dual: bool = False) -> None:
    """`dual`: no --db/--db-url, so the line is read as shell too (simulate
    runs that reading). Here, only the statements that start with an
    UPPERCASE SQL keyword are SQL: `SELECT 1; rm -rf dir` is SELECT for the
    SQL reading and rm for the shell's (review C2a, CR1)."""
    explicit_db, db_url = w.sql_target

    class _Line:                                   # what Session needs from an Invocation
        text = command[:200]
        redirects: list = []
    inv = _Line()
    if db_url:
        sess = Session(w, inv, state, "postgres")
        sess.use_db(pg_target(db_url, None, None, {}))
    elif explicit_db:
        sess = Session(w, inv, state, "sqlite")
        sess.sqlite = sess._path(explicit_db)
    else:
        sess = Session(w, inv, state, "postgres")
        sess.use_db(DbTarget(None, None, False, "postgres",
                             "SQL with no database named (--db / --db-url)"))
        sess.db.label = "db:(unnamed)"
        sess.dbs = {"db:(unnamed)": (sess.db, None)}
    if dual:
        from .simulate import _SQL_LEAD
        sess.keep = lambda piece: (piece.lstrip(" \t\r\n(").split(None, 1) or [""])[0] \
            .rstrip(";(") in _SQL_LEAD
    sess.run_text(command, 0)
    sess.finish()
