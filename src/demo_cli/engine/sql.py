"""SQL, read without running it (Part C2a, 2026-09-28).

A script is split into statements and client meta-commands, and each
statement is classified READ / WRITE / UNKNOWN by what it does, never by
which words appear somewhere in it. Dialects: "sqlite", "postgres", "mysql".

VERIFIED by running (sqlite3 3.46.1; psql 18.4 on a throwaway PostgreSQL 18):
  EXPLAIN ANALYZE <write> executes it (pg); plain EXPLAIN does not.
  A writable CTE inside a SELECT writes (pg); WITH ... DELETE writes (sqlite).
  SELECT ... INTO new_table creates a table (pg).
  writefile() in a SELECT writes a local file; VACUUM INTO writes one (sqlite).
  BEGIN ... ROLLBACK changes nothing - still counted as a write here (may-
  semantics, the safe direction; review C2 Q13).
Imported only when a SQL client or a bare SQL line is met.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .effects import CREATE, DELETE, OVERWRITE

READ, WRITE, UNKNOWN, META = "READ", "WRITE", "UNKNOWN", "META"


class _Rx:
    """A pattern compiled on first use, not at import (review C2a, CR3:
    compiling every pattern at import cost 4-15 ms cold under load)."""
    __slots__ = ("pattern", "flags", "rx")

    def __init__(self, pattern: str, flags: int = 0):
        self.pattern, self.flags, self.rx = pattern, flags, None

    def get(self):
        if self.rx is None:
            self.rx = re.compile(self.pattern, self.flags)
        return self.rx


class Stmt:
    """One statement or client command. `kind`: READ / WRITE / UNKNOWN /
    META. `effect`: DELETE / OVERWRITE / CREATE for a WRITE. `literals`: its
    string literals in order (ATTACH 'x.db', writefile('f'), VACUUM INTO)."""
    __slots__ = ("text", "kind", "effect", "why", "literals", "words")

    def __init__(self, text: str, kind: str, effect: Optional[str] = None, why: str = "",
                 literals: Optional[List[str]] = None, words: Optional[List[str]] = None):
        self.text, self.kind, self.effect, self.why = text, kind, effect, why
        self.literals = literals or []
        self.words = words or []


# ---- splitting ----------------------------------------------------------------

# The next token that can change the splitter's state, per dialect. Plain
# text between them is copied in one slice: a character loop was quadratic
# on long statements (2.3 s for 256 KiB, measured 2026-09-28).
_SPECIAL = {
    "sqlite": _Rx(r"['\";]|--|/\*"),
    "postgres": _Rx(r"['\";$\\]|--|/\*"),
    "mysql": _Rx(r"['\"`;\\#]|--|/\*"),
}
_SPACE = _Rx(r"\s*")


def split(text: str, dialect: str, budget) -> List[Tuple[str, bool]]:
    """(piece, is_meta) in order. SQL pieces end at the delimiter outside
    quotes and comments; a meta-command is its whole line (a sqlite `.cmd`
    or a mysql word command at a statement's start, a psql/mysql `\\cmd`
    anywhere). An unterminated quote or comment makes the rest one piece
    ending in the marker "\\0UNTERMINATED"."""
    out: List[Tuple[str, bool]] = []
    delim = ";"
    buf: List[str] = []
    has = False                        # the current statement holds something
    special = _SPECIAL[dialect].get()
    space, dollar, mysql_cmd = _SPACE.get(), _DOLLAR_TAG.get(), _MYSQL_WORD_CMD.get()
    i, n = 0, len(text)

    def flush() -> None:
        piece = "".join(buf).strip()
        if piece:
            out.append((piece, False))
        buf.clear()

    def unterminated(at: int) -> List[Tuple[str, bool]]:
        buf.append(text[at:])
        out.append(("".join(buf).strip() + "\0UNTERMINATED", False))
        return out

    while i < n:
        budget.check()
        if not has:
            i = space.match(text, i).end()
            if i >= n:
                break
            if (dialect == "sqlite" and text[i] == ".") or \
                    (dialect == "mysql" and mysql_cmd.match(text, i)):
                end = text.find("\n", i)
                end = n if end < 0 else end
                line = text[i:end].strip()
                if dialect == "mysql" and line.lower().startswith("delimiter"):
                    parts = line.split()
                    delim = parts[1] if len(parts) > 1 else ";"
                elif dialect == "mysql" and line.endswith(delim):
                    line = line[:-len(delim)].rstrip()
                out.append((line, True))
                i = end + 1
                continue
        m = special.search(text, i)
        j = m.start() if m else n
        tok = m.group(0) if m else ""
        if delim != ";":
            k = text.find(delim, i)
            if 0 <= k < j:
                j, tok = k, delim
            elif tok == ";":
                tok = ";x"                     # a ';' that is not the delimiter
        if j > i:
            buf.append(text[i:j])
            has = True
        if j >= n:
            break
        i = j
        if tok == delim:
            flush()
            has = False
            i += len(delim)
        elif tok in ("'", '"', "`"):
            k = _close_quote(text, i, tok, dialect)
            if k < 0:
                return unterminated(i)
            buf.append(text[i:k + 1])
            has = True
            i = k + 1
        elif tok == "$":
            mt = dollar.match(text, i)
            if not mt:
                buf.append("$")
                has = True
                i += 1
                continue
            k = text.find(mt.group(0), mt.end())
            if k < 0:
                return unterminated(i)
            buf.append(text[i:k + len(mt.group(0))])
            has = True
            i = k + len(mt.group(0))
        elif tok in ("--", "#"):
            k = text.find("\n", i)
            i = n if k < 0 else k
            buf.append(" ")
        elif tok == "/*":
            k = _close_block_comment(text, i, dialect)
            if k < 0:
                return unterminated(i)
            buf.append(" ")
            i = k
        elif tok == "\\":
            flush()
            has = False
            k = text.find("\n", i)
            k = n if k < 0 else k
            out.append((text[i:k].strip(), True))
            i = k + 1
        else:                                  # ";x"
            buf.append(text[i])
            has = True
            i += 1
    flush()
    return out


_DOLLAR_TAG = _Rx(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$")
_MYSQL_WORD_CMD = _Rx(
    r"(?i)(?:source|system|tee|notee|use|connect|delimiter|charset|pager|nopager|"
    r"prompt|rehash|status|warnings|nowarning|exit|quit|edit|resetconnection)\b")


# A doubled quote escapes it; mysql also takes a backslash escape in '' and "".
_QUOTE_END = {(q, bs): _Rx((r"(?:[^%s\\]|\\.|%s%s)*%s" if bs else r"(?:[^%s]|%s%s)*%s")
                           % (q, q, q, q))
              for q in ("'", '"', "`") for bs in (False, True)}


def _close_quote(text: str, i: int, q: str, dialect: str) -> int:
    m = _QUOTE_END[(q, dialect == "mysql" and q != "`")].get().match(text, i + 1)
    return m.end() - 1 if m else -1


def _close_block_comment(text: str, i: int, dialect: str) -> int:
    depth, j = 0, i
    while j < len(text):
        if text.startswith("/*", j):
            depth += 1 if dialect == "postgres" or depth == 0 else 0
            j += 2
            continue
        if text.startswith("*/", j):
            depth -= 1
            j += 2
            if depth <= 0:
                return j
            continue
        j += 1
    return -1


# ---- classifying -----------------------------------------------------------------

_WORD = _Rx(r"[A-Za-z_][A-Za-z_0-9]*|'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|`[^`]*`|\S")

_READ_LEAD = {"SELECT", "VALUES", "TABLE", "SHOW", "DESCRIBE", "DESC", "BEGIN", "START",
              "COMMIT", "END", "SAVEPOINT", "RELEASE", "SET", "RESET", "LISTEN", "UNLISTEN",
              "ANALYZE", "CHECKPOINT", "DISCARD", "USE", "DEALLOCATE", "LOCK", "FETCH",
              "CLOSE", "DECLARE", "MOVE", "PREPARE", "HANDLER", "CHECKSUM", "ABORT",
              "ROLLBACK"}
_DELETE_LEAD = {"DROP", "TRUNCATE", "DELETE"}
_WRITE_LEAD = {"INSERT", "UPDATE", "REPLACE", "UPSERT", "MERGE", "ALTER", "RENAME", "GRANT",
               "REVOKE", "COMMENT", "REINDEX", "CLUSTER", "REFRESH", "LOAD", "OPTIMIZE",
               "REPAIR", "FLUSH", "KILL", "NOTIFY", "SECURITY", "IMPORT", "INSTALL",
               "UNINSTALL", "ATTACH", "DETACH", "COPY", "VACUUM", "PRAGMA", "CREATE"}
_UNKNOWN_LEAD = {"CALL", "DO", "EXECUTE", "EXEC"}
_DML = {"INSERT", "UPDATE", "DELETE", "MERGE", "UPSERT"}

# Functions with effects outside the query's result.
_WRITE_FUNCS = {"writefile", "setval", "nextval", "lo_unlink", "lo_import", "lo_export",
                "lo_create", "pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf",
                "pg_rotate_logfile", "pg_file_write", "pg_switch_wal", "pg_drop_replication_slot"}
_UNKNOWN_FUNCS = {"load_extension", "edit", "dblink_exec", "dblink", "sys_exec", "sys_eval"}
_READ_PRAGMAS = {"table_info", "table_xinfo", "index_list", "index_info", "index_xinfo",
                 "foreign_key_list", "foreign_key_check", "integrity_check", "quick_check",
                 "compile_options", "database_list", "function_list", "module_list",
                 "pragma_list", "collation_list", "table_list", "stats", "data_version",
                 "freelist_count", "page_count"}


def _unquote(tok: str) -> str:
    q = tok[0]
    return tok[1:-1].replace(q + q, q)


_LEAD = _Rx(r"[\s(]*([A-Za-z_]+)")
# Leads decided by their first word alone - most statements in a script. A
# full token scan of every statement cost ~20 ms per 64 KiB (measured).
_FAST_WRITE = _WRITE_LEAD - {"ATTACH", "COPY", "VACUUM", "PRAGMA", "CREATE"}
_FAST_READ = _READ_LEAD - {"SELECT", "VALUES", "TABLE", "RESET", "SET", "START"}


def classify(text: str, dialect: str) -> Stmt:
    if text.endswith("\0UNTERMINATED"):
        return Stmt(text[:-13], UNKNOWN, why="an unterminated quote or comment")
    m = _LEAD.get().match(text)
    first = m.group(1).upper() if m else ""
    if first in _DELETE_LEAD:
        return Stmt(text, WRITE, DELETE, words=[first])
    if first in _FAST_WRITE:
        return Stmt(text, WRITE, OVERWRITE, words=[first])
    if first in _FAST_READ:
        return Stmt(text, READ, words=[first])
    if first in _UNKNOWN_LEAD:
        return Stmt(text, UNKNOWN, why=f"{first} runs stored code", words=[first])
    toks = _WORD.get().findall(text)
    literals = [_unquote(t) for t in toks if t[0] == "'"]
    words = [t.upper() for t in toks if t[0].isalpha() or t[0] == "_"]
    lower_words = {t.lower() for t in toks if t[0].isalpha() or t[0] == "_"}
    lead = next((t.upper() for t in toks if t != "("), "")

    def st(kind, effect=None, why=""):
        return Stmt(text, kind, effect, why, literals, words)

    if lead == "EXPLAIN":
        inner, analyze = _explain(text)
        if analyze and dialect in ("postgres", "mysql"):
            return classify(inner, dialect)       # VERIFIED (pg): EXPLAIN ANALYZE executes it
        return st(READ)
    if lead == "WITH":
        if _DML & set(words[1:]):
            eff = DELETE if "DELETE" in words else OVERWRITE
            return st(WRITE, eff, "a writable CTE")
        lead = "SELECT"
    if lead in ("SELECT", "VALUES", "TABLE"):
        if lower_words & _UNKNOWN_FUNCS:
            return st(UNKNOWN, why="a function with unknown effects")
        if lower_words & _WRITE_FUNCS:
            return st(WRITE, OVERWRITE, "a function with side effects")
        if dialect in ("postgres", "mysql"):
            impure = _impure_call(text)
            if impure:
                return st(UNKNOWN, why=f"it calls {impure}(), whose effects are unknown")
        if "INTO" in words:
            after = words[words.index("INTO") + 1:words.index("INTO") + 2]
            if dialect == "mysql" and after and after[0] in ("OUTFILE", "DUMPFILE"):
                return st(UNKNOWN, why="SELECT INTO OUTFILE: the server writes a file")
            if dialect == "postgres":
                return st(WRITE, CREATE, "SELECT INTO creates a table")
        return st(READ)
    if lead == "PRAGMA":
        name = words[1].lower() if len(words) > 1 else ""
        if "=" in text:
            return st(WRITE, OVERWRITE)
        if "(" in text and name not in _READ_PRAGMAS:
            return st(WRITE, OVERWRITE, "a pragma with an argument")
        return st(READ)
    if lead == "COPY" and dialect == "postgres":
        if "PROGRAM" in words:
            return st(UNKNOWN, why="COPY ... PROGRAM runs a command on the server")
        if "FROM" in words:
            return st(WRITE, OVERWRITE)
        if "TO" in words and "STDOUT" not in words:
            return st(UNKNOWN, why="COPY ... TO a file: the server writes it")
        return st(READ)
    if lead == "VACUUM":
        return st(WRITE if "INTO" in words else READ, CREATE if "INTO" in words else None)
    if lead == "ROLLBACK":
        return st(READ)
    if lead == "SET":
        # review C2a CR5: mysql's server-wide SET survives the session
        if dialect == "mysql" and (words[1:2] in (["GLOBAL"], ["PERSIST"], ["PERSIST_ONLY"],
                                                  ["PASSWORD"])
                                   or re.search(r"(?i)@@(?:global|persist(?:_only)?)\.", text)):
            return st(WRITE, OVERWRITE, "a server-wide SET")
        return st(READ)
    if lead == "START":
        if words[1:2] == ["TRANSACTION"]:
            return st(READ)
        return st(UNKNOWN, why="START " + " ".join(words[1:3]).lower() + " is not a transaction")
    if lead == "PREPARE":
        return st(READ)
    if lead in _DELETE_LEAD:
        return st(WRITE, DELETE)
    if lead == "CREATE":
        replacing = "REPLACE" in words[1:4] or "OR" in words[1:3]
        return st(WRITE, OVERWRITE if replacing else CREATE)
    if lead == "RESET" and dialect == "mysql" and len(words) > 1 and words[1] in ("MASTER",
                                                                                   "REPLICA",
                                                                                   "SLAVE"):
        return st(WRITE, DELETE)
    if lead in _WRITE_LEAD:
        return st(WRITE, OVERWRITE)
    if lead in _READ_LEAD:
        return st(READ)
    if lead in _UNKNOWN_LEAD:
        return st(UNKNOWN, why=f"{lead} runs stored code")
    return st(UNKNOWN, why=f"an unrecognised statement ({lead or 'empty'})")


# review C2a CR4: a function a SELECT calls may write (a PostgreSQL function, a
# MySQL stored function). Anything off this read-only allowlist is UNKNOWN,
# a may-write. DATA: extend it, with the sample-query test, when a common read
# turns out missing.
PURE_FUNCTIONS = frozenset("""
count sum avg min max array_agg string_agg json_agg jsonb_agg json_object_agg jsonb_object_agg
bool_and bool_or every stddev stddev_pop stddev_samp variance var_pop var_samp percentile_cont
percentile_disc mode rank dense_rank row_number ntile lag lead first_value last_value nth_value
cume_dist percent_rank group_concat bit_and bit_or bit_xor any_value
lower upper length char_length character_length octet_length bit_length substr substring left
right trim ltrim rtrim btrim replace concat concat_ws format position strpos split_part repeat
reverse lpad rpad initcap md5 sha1 sha2 sha224 sha256 sha384 sha512 encode decode to_hex ascii
chr regexp_replace regexp_matches regexp_match regexp_split_to_array regexp_split_to_table
regexp_like regexp_substr regexp_instr regexp_count quote_ident quote_literal quote_nullable
translate starts_with instr locate field find_in_set hex unhex soundex space mid ucase lcase
abs ceil ceiling floor round trunc truncate sign sqrt power pow exp ln log log10 log2 mod pi
random rand greatest least div degrees radians sin cos tan cot asin acos atan atan2 cbrt gcd
lcm width_bucket
now current_date current_time current_timestamp localtime localtimestamp date_trunc date_part
extract age to_char to_date to_timestamp to_number date_add date_sub adddate subdate datediff
date_format timestampdiff timestampadd year month day hour minute second dayofweek dayofmonth
dayofyear week weekday weekofyear unix_timestamp from_unixtime str_to_date make_date make_time
make_timestamp make_timestamptz make_interval justify_days justify_hours justify_interval
clock_timestamp statement_timestamp transaction_timestamp timeofday isfinite date sysdate curdate
curtime utc_timestamp utc_date last_day monthname dayname quarter convert_tz time timestamp
json_build_object jsonb_build_object json_build_array jsonb_build_array to_json to_jsonb
row_to_json array_to_json json_extract json_extract_path json_extract_path_text
jsonb_extract_path jsonb_extract_path_text json_array_length jsonb_array_length json_each
jsonb_each json_each_text jsonb_each_text json_object_keys jsonb_object_keys jsonb_set
jsonb_insert jsonb_pretty json_typeof jsonb_typeof json_object json_array json_unquote
json_contains json_keys json_length json_valid json_value json_query jsonb_path_query
jsonb_path_exists jsonb_strip_nulls json_strip_nulls json_agg_strict json_populate_record
jsonb_populate_record json_to_record jsonb_to_record json_array_elements jsonb_array_elements
json_array_elements_text jsonb_array_elements_text
cast convert coalesce nullif ifnull isnull nvl if iif typeof pg_typeof text int integer float
numeric decimal bigint smallint boolean varchar char binary
array_length array_upper array_lower array_ndims array_dims cardinality unnest array_position
array_positions array_append array_prepend array_cat array_remove array_replace string_to_array
array_to_string generate_series generate_subscripts
version current_setting current_user current_role current_schema current_schemas
current_database current_catalog session_user user database schema pg_size_pretty
pg_database_size pg_relation_size pg_table_size pg_indexes_size pg_total_relation_size
pg_column_size has_table_privilege has_schema_privilege has_database_privilege
has_column_privilege has_function_privilege has_sequence_privilege pg_has_role pg_get_viewdef
pg_get_functiondef pg_get_function_arguments pg_get_indexdef pg_get_constraintdef
pg_get_triggerdef pg_get_expr pg_get_userbyid pg_get_serial_sequence pg_backend_pid
pg_postmaster_start_time pg_is_in_recovery pg_current_wal_lsn pg_last_wal_receive_lsn
inet_server_addr inet_server_port inet_client_addr obj_description col_description
shobj_description pg_table_is_visible format_type to_regclass to_regtype to_regproc
pg_encoding_to_char pg_sleep sleep connection_id last_insert_id found_rows row_count uuid
gen_random_uuid uuid_generate_v4 random_uuid txid_current_if_assigned pg_client_encoding
""".split())

# Keywords a '(' may follow in a query; they are syntax, not calls.
_NOT_CALLS = frozenset("""
in exists any all some values as from join using on and or not where select over filter
within array row lateral distinct when then else case interval position overlay grouping
rollup cube sets union intersect except table by is like ilike similar between partition order
limit offset having window range rows returning conflict do set into with recursive
materialized null true false default for of fetch only unique primary key references check
constraint index escape collate at zone
""".split())
_CALL = _Rx(r"([A-Za-z_][\w$]*)\s*(\.\s*[A-Za-z_][\w$]*)?\s*\(")
_STRINGS = _Rx(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|\$(\w*)\$.*?\$\1\$", re.S)


def _impure_call(text: str) -> Optional[str]:
    """The first function the query calls that is not known to be pure."""
    masked = _STRINGS.get().sub(" '' ", text)
    for m in _CALL.get().finditer(masked):
        first, second = m.group(1).lower(), m.group(2)
        if not second and _column_list(masked, m):
            continue
        if second:
            name = second.lstrip(". \t").lower()
            if first == "pg_catalog" and name in PURE_FUNCTIONS:
                continue
            return f"{first}.{name}"
        if first in _NOT_CALLS or first in PURE_FUNCTIONS:
            continue
        return first
    return None


_PREV_WORD = _Rx(r"([A-Za-z_]+)\s*$")
_CTE_BODY = _Rx(r"\s*AS\s+(?:NOT\s+)?(?:MATERIALIZED\s+)?\(", re.I)


def _column_list(masked: str, m) -> bool:
    """`name(` that is not a call (review C2a, CR6): an alias column list
    (`AS g(n)`), or a CTE with columns - `name(cols) AS [NOT] [MATERIALIZED] (`
    - which a select-list `f(x) AS alias` never is (a name follows its AS)."""
    prev = _PREV_WORD.get().search(masked, 0, m.start())
    if prev and prev.group(1).upper() == "AS":
        return True
    depth, k = 0, m.end() - 1
    while k < len(masked):
        depth += (masked[k] == "(") - (masked[k] == ")")
        if depth == 0:
            break
        k += 1
    return bool(_CTE_BODY.get().match(masked, k + 1))


def warm(dialect: str) -> None:
    """Compile what the analysis of `dialect` needs - called before the
    budget's clock starts (review C2a, CR3)."""
    for rx in (_SPECIAL[dialect], _SPACE, _DOLLAR_TAG, _MYSQL_WORD_CMD, _WORD, _LEAD, _CALL,
               _STRINGS, _PREV_WORD, _CTE_BODY):
        rx.get()
    for rx in _QUOTE_END.values():
        rx.get()


def _explain(text: str) -> Tuple[str, bool]:
    """(the explained statement, whether ANALYZE executes it). Forms:
    EXPLAIN [ANALYZE] [VERBOSE] stmt; EXPLAIN (ANALYZE [true|on], ...) stmt."""
    rest = re.sub(r"(?is)^\s*EXPLAIN\b", "", text).lstrip()
    if rest.startswith("("):
        depth = 0
        for k, c in enumerate(rest):
            depth += (c == "(") - (c == ")")
            if depth == 0:
                opts, rest = rest[1:k], rest[k + 1:]
                break
        else:
            return rest, False
        on = False
        for opt in opts.split(","):
            words = opt.split()
            if words and words[0].upper() == "ANALYZE":
                on = len(words) == 1 or words[1].lower() in ("true", "on", "1")
        return rest.strip(), on
    analyze = False
    while True:
        m = re.match(r"(?is)(ANALYZE|ANALYSE|VERBOSE|QUERY\s+PLAN|FORMAT\s*=\s*\w+)\b\s*", rest)
        if not m:
            return rest, analyze
        analyze = analyze or m.group(1).upper().startswith("ANALY")
        rest = rest[m.end():]


def statements(text: str, dialect: str, budget) -> List[Tuple[str, Optional[Stmt]]]:
    """[(meta line, None) | (sql text, Stmt)] in order."""
    out: List[Tuple[str, Optional[Stmt]]] = []
    for piece, is_meta in split(text, dialect, budget):
        budget.check()
        out.append((piece, None) if is_meta else (piece, classify(piece, dialect)))
    return out
