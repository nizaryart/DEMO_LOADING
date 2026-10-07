"""What a data-store CLI does (M2.2b3): redis-cli, mongosh / mongo, the
PostgreSQL tools dropdb / pg_restore / pg_dump, mysqladmin and sqlcmd.

A data store's content lives behind a server no local copy restores, so a
change there is `reach(label, kind)` and policy.py decides it; a local file a
tool writes (pg_dump -f, redis-cli --rdb) goes through the world primitives.
Labels: `flush:` -> datastore_flush (a whole keyspace emptied), `db:` ->
remote_database (every other write), `cred:` -> credential_rotation.

WHAT IT CLAIMS, AND WHAT IT DOES NOT. As every family: anything not listed is
`uncovered` and today's text path decides the line unchanged. Code the engine
cannot read is RUN, which escalates: redis EVAL / FCALL / --eval, a mongosh
--eval or script file, a T-SQL statement the SQL reader does not know.
Commands read from stdin (`redis-cli` with no command, `--pipe`, `mongosh`
without --eval) are not understood. Creations (createdb, mysqladmin create,
sqlcmd create) are not claimed.

VERIFIED (2026-10-07), from each tool's own data, never against a server:
  - redis 8.10.2: the WRITE / READONLY / SCRIPT_RUNNER flag of every one of
    its 459 commands from src/commands/*.json; redis-cli's option table from
    parseOptions() in src/redis-cli.c (options stop at the first word that
    is not one; that word is the command, case-insensitive).
  - mongosh 2.13.0: its --help. mongo (the legacy shell, no binary any more)
    follows ruling R4: only its escalating forms are claimed.
  - dropdb / pg_restore / pg_dump 18.4: their --help (getopt_long: options
    anywhere). pg_restore --clean drops objects first; without -d it only
    writes a script.
  - mysqladmin: the MySQL client option parser, shared with `mysql` (C2a's
    MYSQL_OPTIONS, verified=False there too) - ruling R4 again: drop /
    shutdown / kill / password are claimed, nothing that would allow.
  - go-sqlcmd 1.10.0: its --help; the SQL in -Q / -q goes through C2a's
    statement reader (sql.statements) with the sqlite splitting rules
    (T-SQL has no dollar quoting).
"""
from __future__ import annotations

import json
import os
from typing import Dict, FrozenSet, List, Optional, Tuple

from ..model import Word
from .cloud_ops import READ, _local, _reach, _split
from .effects import CREATE, DELETE, OVERWRITE, RUN, SEND, SERVICE_LOSS

# ---------------------------------------------------------------- redis-cli

# redis-cli parseOptions() (redis 8.10.2).
_RCLI_VALUES = frozenset({
    "--cacert", "--cacertdir", "--cert", "--cluster", "--cluster-from", "--cluster-from-pass",
    "--cluster-from-user", "--cluster-master-id", "--cluster-pipeline", "--cluster-replicas",
    "--cluster-slots", "--cluster-threshold", "--cluster-timeout", "--cluster-to",
    "--cluster-weight", "--count", "--cursor", "--eval", "--functions-rdb", "--intrinsic-latency",
    "--key", "--keystats-samples", "--latency-percentiles", "--lru-test", "--memkeys-samples",
    "--name", "--pass", "--pattern", "--pipe-timeout", "--quoted-pattern", "--rdb", "--show-pushes",
    "--sni", "--test_hint", "--test_hint_file", "--tls-ciphers", "--tls-ciphersuites", "--top",
    "--user", "--vset-recall", "--vset-recall-count", "--vset-recall-ef", "--vset-recall-ele",
    "-D", "-X", "-a", "-d", "-h", "-i", "-n", "-p", "-r", "-s", "-t", "-u"})
_RCLI_FLAGS = frozenset({
    "--askpass", "--bigkeys", "--cluster-copy", "--cluster-fix-with-unreachable-masters",
    "--cluster-from-askpass", "--cluster-only-masters", "--cluster-only-replicas",
    "--cluster-replace", "--cluster-search-multiple-owners", "--cluster-simulate", "--cluster-slave",
    "--cluster-use-empty-masters", "--cluster-yes", "--csv", "--help", "--hotkeys", "--insecure",
    "--json", "--keystats", "--latency", "--latency-dist", "--latency-history", "--ldb",
    "--ldb-sync-mode", "--memkeys", "--mono", "--no-auth-warning", "--no-raw", "--pipe",
    "--quoted-input", "--quoted-json", "--raw", "--replica", "--scan", "--slave", "--stat", "--tls",
    "--verbose", "--version", "-2", "-3", "-4", "-6", "-c", "-e", "-v", "-x"})
_RCLI_READ_MODES = frozenset({"--scan", "--bigkeys", "--memkeys", "--hotkeys", "--keystats",
                              "--stat", "--latency", "--latency-history", "--latency-dist",
                              "--intrinsic-latency", "--lru-test"})
# redis src/commands/*.json: the WRITE / READONLY / SCRIPT_RUNNER commands.
_RCLI_WRITE = frozenset({
    "APPEND", "ARDEL", "ARDELRANGE", "ARINSERT", "ARMSET", "ARRING", "ARSEEK", "ARSET",
    "BITFIELD", "BITOP", "BLMOVE", "BLMOVEM", "BLMPOP", "BLPOP", "BRPOP", "BRPOPLPUSH",
    "BZMPOP", "BZPOPMAX", "BZPOPMIN", "COPY", "DECR", "DECRBY", "DEL", "DELEX",
    "EXPIRE", "EXPIREAT", "FLUSHALL", "FLUSHDB", "FUNCTION DELETE", "FUNCTION FLUSH",
    "FUNCTION LOAD", "FUNCTION RESTORE", "GEOADD", "GEORADIUS", "GEORADIUSBYMEMBER",
    "GEOSEARCHSTORE", "GETDEL", "GETEX", "GETSET", "HDEL", "HEXPIRE", "HEXPIREAT",
    "HGETDEL", "HGETEX", "HIMPORT SET", "HINCRBY", "HINCRBYFLOAT", "HMSET", "HPERSIST",
    "HPEXPIRE", "HPEXPIREAT", "HSET", "HSETEX", "HSETNX", "INCR", "INCRBY",
    "INCRBYFLOAT", "INCREX", "LINSERT", "LMOVE", "LMOVEM", "LMPOP", "LPOP", "LPUSH",
    "LPUSHX", "LREM", "LSET", "LTRIM", "MIGRATE", "MOVE", "MSET", "MSETEX", "MSETNX",
    "PERSIST", "PEXPIRE", "PEXPIREAT", "PFADD", "PFDEBUG", "PFMERGE", "PSETEX",
    "RENAME", "RENAMENX", "RESTORE", "RESTORE-ASKING", "RPOP", "RPOPLPUSH", "RPUSH",
    "RPUSHX", "SADD", "SDIFFSTORE", "SET", "SETBIT", "SETEX", "SETNX", "SETRANGE",
    "SFLUSH", "SINTERSTORE", "SMOVE", "SORT", "SPOP", "SREM", "SUNIONSTORE", "SWAPDB",
    "TRIMSLOTS", "UNLINK", "XACK", "XACKDEL", "XADD", "XAUTOCLAIM", "XCFGSET",
    "XCLAIM", "XDEL", "XDELEX", "XGROUP CREATE", "XGROUP CREATECONSUMER",
    "XGROUP DELCONSUMER", "XGROUP DESTROY", "XGROUP SETID", "XIDMPRECORD", "XNACK",
    "XREADGROUP", "XSETID", "XTRIM", "ZADD", "ZDIFFSTORE", "ZINCRBY", "ZINTERSTORE",
    "ZMPOP", "ZPOPMAX", "ZPOPMIN", "ZRANGESTORE", "ZREM", "ZREMRANGEBYLEX",
    "ZREMRANGEBYRANK", "ZREMRANGEBYSCORE", "ZUNIONSTORE"})
_RCLI_READONLY = frozenset({
    "ARCOUNT", "ARGET", "ARGETRANGE", "ARGREP", "ARINFO", "ARLASTITEMS", "ARLEN",
    "ARMGET", "ARNEXT", "AROP", "ARSCAN", "BITCOUNT", "BITFIELD_RO", "BITPOS",
    "DBSIZE", "DIGEST", "DUMP", "EVALSHA_RO", "EVAL_RO", "EXISTS", "EXPIRETIME",
    "FCALL_RO", "GEODIST", "GEOHASH", "GEOPOS", "GEORADIUSBYMEMBER_RO", "GEORADIUS_RO",
    "GEOSEARCH", "GET", "GETBIT", "GETRANGE", "HEXISTS", "HEXPIRETIME", "HGET",
    "HGETALL", "HKEYS", "HLEN", "HMGET", "HPEXPIRETIME", "HPTTL", "HRANDFIELD",
    "HSCAN", "HSTRLEN", "HTTL", "HVALS", "KEYS", "LCS", "LINDEX", "LLEN", "LOLWUT",
    "LPOS", "LRANGE", "MEMORY USAGE", "MGET", "OBJECT ENCODING", "OBJECT FREQ",
    "OBJECT IDLETIME", "OBJECT REFCOUNT", "PEXPIRETIME", "PFCOUNT", "PTTL",
    "RANDOMKEY", "SCAN", "SCARD", "SDIFF", "SDIFFCARD", "SINTER", "SINTERCARD",
    "SISMEMBER", "SMEMBERS", "SMISMEMBER", "SORT_RO", "SRANDMEMBER", "SSCAN", "STRLEN",
    "SUBSTR", "SUNION", "SUNIONCARD", "TOUCH", "TTL", "TYPE", "XINFO CONSUMERS",
    "XINFO GROUPS", "XINFO STREAM", "XLEN", "XPENDING", "XRANGE", "XREAD", "XREVRANGE",
    "ZCARD", "ZCOUNT", "ZDIFF", "ZINTER", "ZINTERCARD", "ZLEXCOUNT", "ZMSCORE",
    "ZRANDMEMBER", "ZRANGE", "ZRANGEBYLEX", "ZRANGEBYSCORE", "ZRANK", "ZREVRANGE",
    "ZREVRANGEBYLEX", "ZREVRANGEBYSCORE", "ZREVRANK", "ZSCAN", "ZSCORE", "ZUNION"})
_RCLI_SCRIPT = frozenset({
    "EVAL", "EVALSHA", "EVALSHA_RO", "EVAL_RO", "FCALL", "FCALL_RO"})
_RCLI_FLUSH = frozenset({"FLUSHALL", "FLUSHDB", "FUNCTION FLUSH", "SCRIPT FLUSH"})
# Commands with neither flag, read by name (admin / cluster / client reads).
_RCLI_ADMIN_READ = frozenset({
    "PING", "ECHO", "INFO", "TIME", "LASTSAVE", "ROLE", "HELLO", "AUTH", "SELECT", "QUIT",
    "MONITOR", "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE", "UNSUBSCRIBE", "PUNSUBSCRIBE",
    "SUNSUBSCRIBE", "WAIT", "WAITAOF", "READONLY", "READWRITE", "ASKING",
    "COMMAND", "COMMAND COUNT", "COMMAND DOCS", "COMMAND GETKEYS", "COMMAND GETKEYSANDFLAGS",
    "COMMAND INFO", "COMMAND LIST", "COMMAND HELP", "CONFIG GET", "CONFIG HELP",
    "CLIENT LIST", "CLIENT INFO", "CLIENT GETNAME", "CLIENT ID", "CLIENT HELP",
    "CLIENT TRACKINGINFO", "CLIENT GETREDIR", "CLUSTER INFO", "CLUSTER NODES", "CLUSTER SLOTS",
    "CLUSTER SHARDS", "CLUSTER MYID", "CLUSTER MYSHARDID", "CLUSTER KEYSLOT",
    "CLUSTER COUNTKEYSINSLOT", "CLUSTER GETKEYSINSLOT", "CLUSTER REPLICAS", "CLUSTER SLAVES",
    "CLUSTER LINKS", "CLUSTER HELP", "CLUSTER COUNT-FAILURE-REPORTS", "CLUSTER SLOT-STATS",
    "ACL LIST", "ACL USERS", "ACL WHOAMI", "ACL CAT", "ACL GETUSER", "ACL LOG", "ACL HELP",
    "ACL DRYRUN", "ACL GENPASS", "MEMORY USAGE", "MEMORY STATS", "MEMORY DOCTOR", "MEMORY HELP",
    "MEMORY MALLOC-STATS", "LATENCY LATEST", "LATENCY HISTORY", "LATENCY GRAPH", "LATENCY DOCTOR",
    "LATENCY HISTOGRAM", "LATENCY HELP", "SLOWLOG GET", "SLOWLOG LEN", "SLOWLOG HELP",
    "MODULE LIST", "MODULE HELP", "FUNCTION LIST", "FUNCTION DUMP", "FUNCTION STATS",
    "FUNCTION HELP", "SCRIPT EXISTS", "SCRIPT HELP", "OBJECT ENCODING", "OBJECT FREQ",
    "OBJECT IDLETIME", "OBJECT REFCOUNT", "OBJECT HELP", "PUBSUB CHANNELS", "PUBSUB NUMPAT",
    "PUBSUB NUMSUB", "PUBSUB SHARDCHANNELS", "PUBSUB SHARDNUMSUB", "PUBSUB HELP"})
_RCLI_ADMIN_KIND = {
    "SHUTDOWN": SERVICE_LOSS, "CLIENT KILL": SERVICE_LOSS, "CLIENT PAUSE": SERVICE_LOSS,
    "CONFIG SET": OVERWRITE, "CONFIG REWRITE": OVERWRITE, "CONFIG RESETSTAT": OVERWRITE,
    "REPLICAOF": OVERWRITE, "SLAVEOF": OVERWRITE, "FAILOVER": OVERWRITE, "DEBUG": OVERWRITE,
    "CLUSTER RESET": OVERWRITE, "CLUSTER FAILOVER": OVERWRITE, "CLUSTER FORGET": OVERWRITE,
    "CLUSTER DELSLOTS": OVERWRITE, "CLUSTER DELSLOTSRANGE": OVERWRITE,
    "CLUSTER FLUSHSLOTS": OVERWRITE, "CLUSTER ADDSLOTS": OVERWRITE,
    "CLUSTER ADDSLOTSRANGE": OVERWRITE, "CLUSTER MEET": OVERWRITE, "CLUSTER REPLICATE": OVERWRITE,
    "CLUSTER SETSLOT": OVERWRITE, "MODULE LOAD": RUN, "MODULE LOADEX": RUN,
    "MODULE UNLOAD": OVERWRITE, "PUBLISH": SEND, "SPUBLISH": SEND,
    "ACL SETUSER": OVERWRITE, "ACL DELUSER": DELETE, "ACL LOAD": OVERWRITE}
_RCLI_CRED = frozenset({"ACL SETUSER", "ACL DELUSER", "ACL LOAD"})
_RCLI_DELETES = frozenset({"DEL", "UNLINK", "GETDEL", "HDEL", "SREM", "ZREM", "LREM", "XDEL",
                           "FUNCTION DELETE", "ZREMRANGEBYSCORE", "ZREMRANGEBYRANK",
                           "ZREMRANGEBYLEX", "DELEX", "ARDEL", "ARDELRANGE"})


def _rcli_kind(words: List[str]) -> Optional[str]:
    """The kind of one redis command (its words upper-cased)."""
    one = words[0] if words else ""
    two = " ".join(words[:2]) if len(words) > 1 else one
    for name in (two, one):
        if name in _RCLI_FLUSH:
            return "FLUSH"
        if name in _RCLI_SCRIPT:
            return RUN
        if name in _RCLI_WRITE:
            return DELETE if name in _RCLI_DELETES else OVERWRITE
        if name in _RCLI_READONLY or name in _RCLI_ADMIN_READ:
            return READ
        if name in _RCLI_ADMIN_KIND:
            return _RCLI_ADMIN_KIND[name]
    return None


def redis_cli(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    i, got = 0, {}
    while i < len(args):
        a = args[i]
        v = a.value
        if a.expands and not v.startswith("-"):
            break
        if not v.startswith("-") or v == "-":
            break
        if v in _RCLI_VALUES:
            if i + 1 >= len(args):
                return w.impact.not_covered("redis-cli (option)")
            got[v] = args[i + 1]
            i += 2
            continue
        if v in _RCLI_FLAGS:
            got[v] = None
            i += 1
            continue
        return w.impact.not_covered("redis-cli (option)")
    rest = args[i:]
    if "--help" in got or "--version" in got or "-v" in got:
        return
    host = got.get("-h") or got.get("-u") or got.get("-s")
    where = (host.raw if host is not None else "localhost")
    if "--rdb" in got and got["--rdb"] is not None:
        _local(w, inv, state, got["--rdb"], OVERWRITE, tool)
    if "--functions-rdb" in got and got["--functions-rdb"] is not None:
        _local(w, inv, state, got["--functions-rdb"], OVERWRITE, tool)
    if "--eval" in got:
        return _reach(w, inv, f"db:redis://{where}", RUN, args, tool)   # an unread Lua script
    if "--pipe" in got:
        w.impact.not_understood(inv.text, "the commands redis-cli --pipe reads from stdin")
        return
    if "--cluster" in got:
        sub = got["--cluster"]
        if sub is None or sub.expands:
            w.impact.not_understood(inv.text, "the redis-cli --cluster subcommand")
            return
        if sub.value.lower() in ("check", "info", "help"):
            return
        if sub.value.lower() == "call":
            # --cluster call <host:port> <command> [args]: the command runs on every node
            if not rest or rest[0].expands:
                w.impact.not_understood(inv.text, "the redis-cli --cluster call node")
                return
            where, rest = rest[0].raw, rest[1:]
        else:
            return _reach(w, inv, f"db:redis://{where}", OVERWRITE, args, tool)
    if _RCLI_READ_MODES & set(got) and not rest:
        return
    if "--rdb" in got or "--functions-rdb" in got:
        return
    if not rest:
        w.impact.not_understood(inv.text, "redis-cli with no command reads its commands from stdin")
        return
    if any(a.expands for a in rest[:2]):
        w.impact.not_understood(inv.text, "a redis command named by an expansion")
        return
    kind = _rcli_kind([a.value.upper() for a in rest[:2]])
    if kind is None:
        return w.impact.not_covered(f"redis-cli {rest[0].value.upper()}")
    if kind == "FLUSH":
        return _reach(w, inv, f"flush:redis://{where}", DELETE, args, tool)
    name = " ".join(a.value.upper() for a in rest[:2])
    prefix = "cred" if any(name.startswith(c) for c in _RCLI_CRED) else "db"
    _reach(w, inv, f"{prefix}:redis://{where}", kind, rest[1:], tool)


# ---------------------------------------------------------------- mongosh / mongo

# mongosh 2.13.0 --help (`[arg]` marks a value).
_MONGO_VALUES = frozenset({
    "--apiVersion", "--authenticationDatabase", "--authenticationMechanism",
    "--awsAccessKeyId", "--awsIamSessionToken", "--awsSecretAccessKey",
    "--awsSessionToken", "--gssapiServiceName", "--host", "--keyVaultNamespace",
    "--kmsURL", "--port", "--sspiHostnameCanonicalization", "--sspiRealmOverride",
    "--tlsCAFile", "--tlsCRLFile", "--tlsCertificateKeyFile",
    "--tlsCertificateKeyFilePassword", "--tlsCertificateSelector",
    "--tlsDisabledProtocols", "--username", "-u"})
_MONGO_FLAGS = frozenset({
    "--apiDeprecationErrors", "--apiStrict", "--build-info", "--deep-inspect",
    "--help", "--json", "--nodb", "--norc", "--oidcDumpTokens", "--oidcFlows",
    "--oidcIdTokenAsAccessToken", "--oidcNoNonce", "--oidcRedirectUri",
    "--oidcTrustedEndpoint", "--quiet", "--retryWrites", "--shell", "--tls",
    "--tlsAllowInvalidCertificates", "--tlsAllowInvalidHostnames", "--tlsFIPSMode",
    "--version", "-h"})


def mongosh(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    if any(a.value in ("-h", "--help", "--version") and not a.expands for a in args):
        return
    evals, files, positional = [], [], []
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        name, eq, glued = v.partition("=")
        if name == "--eval":
            evals.append(a)
            i += 1 if eq else 2
            continue
        if name in ("-f", "--file"):
            files.append(a)
            i += 1 if eq else 2
            continue
        if name in ("-p", "--password"):
            i += 1 if eq else 2                                 # VERIFIED: takes [arg]
            continue
        if name in _MONGO_VALUES:
            i += 1 if eq else 2
            continue
        if name in _MONGO_FLAGS:
            i += 1
            continue
        if v.startswith("-") and not a.expands:
            return w.impact.not_covered(f"{tool} (option)")
        positional.append(a)
        i += 1
    host = next((p.raw for p in positional if not p.value.endswith(".js")), "localhost")
    scripts = [p for p in positional if p.value.endswith(".js")]
    if evals or files or scripts:
        return _reach(w, inv, f"db:mongodb://{host}", RUN, [], tool)   # unread JavaScript
    w.impact.not_understood(inv.text, f"{tool} without --eval reads its commands from stdin")


# ---------------------------------------------------------------- PostgreSQL tools

_PG_VALUES = {
    "dropdb": frozenset({"--host", "--maintenance-db", "--port", "--username", "-U", "-h", "-p"}),
    "pg_restore": frozenset({"--dbname", "--exclude-schema", "--file", "--filter", "--format",
                             "--function", "--host", "--index", "--jobs", "--port", "--restrict-key",
                             "--role", "--schema", "--section", "--superuser", "--table",
                             "--transaction-size", "--trigger", "--use-list", "--username", "-F",
                             "-I", "-L", "-N", "-P", "-S", "-T", "-U", "-d", "-f", "-h", "-j", "-n",
                             "-p", "-t"}),
    "pg_dump": frozenset({"--compress", "--dbname", "--encoding", "--exclude-extension",
                          "--exclude-schema", "--exclude-table", "--exclude-table-and-children",
                          "--exclude-table-data", "--exclude-table-data-and-children", "--extension",
                          "--extra-float-digits", "--file", "--filter", "--format", "--host",
                          "--include-foreign-data", "--jobs", "--lock-wait-timeout", "--port",
                          "--restrict-key", "--role", "--rows-per-insert", "--schema", "--section",
                          "--snapshot", "--superuser", "--sync-method", "--table",
                          "--table-and-children", "--username", "-E", "-F", "-N", "-S", "-T", "-U",
                          "-Z", "-d", "-e", "-f", "-h", "-j", "-n", "-p", "-t"}),
}
_PG_FLAGS = {
    "dropdb": frozenset({"--echo", "--force", "--if-exists", "--interactive", "--no-password",
                         "--password", "--version", "-V", "-W", "-e", "-f", "-i", "-w", "--help",
                         "-?"}),
    "pg_restore": frozenset({
        "--clean", "--create", "--data-only", "--disable-triggers", "--enable-row-security",
        "--exit-on-error", "--if-exists", "--list", "--no-comments", "--no-data",
        "--no-data-for-failed-tables", "--no-owner", "--no-password", "--no-policies",
        "--no-privileges", "--no-publications", "--no-schema", "--no-security-labels",
        "--no-statistics", "--no-subscriptions", "--no-table-access-method", "--no-tablespaces",
        "--password", "--schema-only", "--single-transaction", "--statistics", "--statistics-only",
        "--strict-names", "--use-set-session-authorization", "--verbose", "--version", "-1", "-C",
        "-O", "-V", "-W", "-a", "-c", "-e", "-l", "-s", "-v", "-w", "-x", "--help", "-?"}),
    "pg_dump": frozenset({
        "--binary-upgrade", "--blobs", "--clean", "--column-inserts", "--create", "--data-only",
        "--disable-dollar-quoting", "--disable-triggers", "--enable-row-security", "--if-exists",
        "--inserts", "--large-objects", "--load-via-partition-root", "--no-blobs", "--no-comments",
        "--no-data", "--no-large-objects", "--no-owner", "--no-password", "--no-policies",
        "--no-privileges", "--no-publications", "--no-schema", "--no-security-labels",
        "--no-statistics", "--no-subscriptions", "--no-sync", "--no-table-access-method",
        "--no-tablespaces", "--no-toast-compression", "--no-unlogged-table-data",
        "--on-conflict-do-nothing", "--password", "--quote-all-identifiers", "--schema-only",
        "--sequence-data", "--serializable-deferrable", "--statistics", "--statistics-only",
        "--strict-names", "--use-set-session-authorization", "--verbose", "--version", "-B", "-C",
        "-O", "-V", "-W", "-a", "-b", "-c", "-s", "-v", "-w", "-x", "--help", "-?"}),
}


def _pg_target(got: Dict[str, Optional[Word]], db: Optional[str]) -> str:
    host = got.get("-h") or got.get("--host")
    return "db:postgres://" + (host.raw if host is not None else "localhost") + "/" + (db or "")


def pg_tool(w, inv, parsed, state, tool) -> None:
    pos, got, bad = _split(list(inv.argv[1:]), _PG_VALUES[tool], _PG_FLAGS[tool])
    if bad is not None:
        return w.impact.not_covered(f"{tool} (option)")
    if set(got) & {"--help", "-?", "--version", "-V"}:
        return
    if tool == "dropdb":
        if not pos:
            return
        return _reach(w, inv, _pg_target(got, pos[0].raw), DELETE, inv.argv[1:], tool)
    if tool == "pg_dump":
        out = got.get("-f") or got.get("--file")
        if out is not None:
            fmt = got.get("-F") or got.get("--format")
            _local(w, inv, state, out, OVERWRITE, tool,
                   whole=fmt is not None and fmt.value.lower().startswith("d"))
        return                                                  # the dump only reads the database
    # pg_restore
    if set(got) & {"-l", "--list"}:
        return
    dbw = got.get("-d") or got.get("--dbname")
    if dbw is None:
        out = got.get("-f") or got.get("--file")
        if out is not None and out.value != "-":
            _local(w, inv, state, out, OVERWRITE, tool)
        return                                                  # a script only, no database
    kind = DELETE if set(got) & {"-c", "--clean"} else OVERWRITE
    _reach(w, inv, _pg_target(got, dbw.raw), kind, inv.argv[1:], tool)


# ---------------------------------------------------------------- mysqladmin

def mysqladmin(w, inv, parsed, state, tool) -> None:
    """Ruling R4: the MySQL option grammar is documentation-only here, so only
    the escalating commands are claimed."""
    from .rules_sql import MYSQL_OPTIONS
    from .invocation import parse_options
    p = parse_options(list(inv.argv[1:]), MYSQL_OPTIONS)
    if p.unknown_options:
        return w.impact.not_covered("mysqladmin (option)")
    ops = [o for o in p.operands]
    if not ops or ops[0].expands:
        return w.impact.not_covered("mysqladmin")
    host = p.options["host"][0] if p.options.get("host") else None
    where = host.raw if host is not None else "localhost"
    cmd = ops[0].value.lower()
    if cmd == "drop" and len(ops) > 1:
        return _reach(w, inv, f"db:mysql://{where}/{ops[1].raw}", DELETE, inv.argv[1:], tool)
    if cmd in ("shutdown", "kill"):
        return _reach(w, inv, f"db:mysql://{where}", SERVICE_LOSS, inv.argv[1:], tool)
    if cmd in ("password", "old-password"):
        return _reach(w, inv, f"cred:mysql://{where}", OVERWRITE, inv.argv[1:], tool)
    w.impact.not_covered(f"mysqladmin {cmd}")


# ---------------------------------------------------------------- sqlcmd

# go-sqlcmd 1.10.0: its flag declarations (cmd/sqlcmd/sqlcmd.go).
_SQLCMD_VALUES = frozenset({
    "--application-intent", "--authentication-method", "--batch-terminator",
    "--change-password", "--change-password-exit", "--column-separator",
    "--database-name", "--driver-logging-level", "--encrypt-connection",
    "--error-level", "--error-severity-level", "--headers",
    "--host-name-in-certificate", "--initial-query", "--input-file", "--list-servers",
    "--login-timeOut", "--output-file", "--packet-size", "--password", "--query",
    "--query-timeout", "--server", "--server-certificate", "--server-name",
    "--trace-file", "--user-name", "--variables", "--workstation-name", "-F", "-H",
    "-J", "-K", "-L", "-N", "-P", "-Q", "-S", "-U", "-V", "-Z", "-a", "-c", "-d", "-h",
    "-i", "-l", "-m", "-o", "-q", "-s", "-t", "-v", "-z"})
_SQLCMD_FLAGS = frozenset({
    "--dedicated-admin-connection", "--disable-variable-substitution", "--echo-input",
    "--enable-column-encryption", "--exit-on-error", "--help", "--trim-spaces",
    "--trust-server-certificate", "--unicode-output-file", "--use-aad",
    "--use-trusted-connection", "--version", "--vertical", "-?", "-A", "-C", "-E",
    "-G", "-W", "-b", "-e", "-g", "-u", "-x"})
_SQLCMD_DATA_DIALECT = "sqlite"


def _sqlcmd_text(w, inv, text: Word, tool: str, where: str, terminator: str = "GO") -> None:
    if text.expands:
        w.impact.not_understood(inv.text, "the SQL sqlcmd runs is named by an expansion")
        return
    body = "\n".join(l for l in text.value.splitlines() if l.strip().upper() != terminator.upper())
    if any(l.strip().startswith(("!!", ":!!", ":r", ":R", ":out", ":Out", ":error"))
           for l in text.value.splitlines()):
        w.impact.not_understood(inv.text, "a sqlcmd command (shell, include, output) in the query")
        return
    from . import sql
    w.untimed(lambda: sql.warm(_SQLCMD_DATA_DIALECT))         # compiles outside the budget
    worst: Optional[str] = None
    order = (DELETE, OVERWRITE, RUN, CREATE)
    for _t, st in sql.statements(body, _SQLCMD_DATA_DIALECT, w.budget):
        if st is None or st.kind == "UNKNOWN":
            kind = RUN
        elif st.kind in ("READ", "META"):
            continue
        else:
            kind = st.effect or OVERWRITE
        if worst is None or order.index(kind) < order.index(worst):
            worst = kind
    if worst is None:
        return
    if worst == CREATE:
        return w.impact.not_covered("sqlcmd (a creation)")
    _reach(w, inv, f"db:mssql://{where}", worst, [], tool)


def sqlcmd(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    if not args or any(a.value in ("-?", "--help", "--version") for a in args):
        return
    if not args[0].value.startswith("-"):
        sub = args[0].value
        if sub == "query" and len(args) > 1:
            return _sqlcmd_text(w, inv, args[1], tool, "current")
        if sub in ("delete", "uninstall", "drop"):
            return _reach(w, inv, "db:mssql://local-container", DELETE, args, tool)
        if sub == "stop":
            return _reach(w, inv, "db:mssql://local-container", SERVICE_LOSS, args, tool)
        return w.impact.not_covered(f"sqlcmd {sub}")
    pos, got, bad = _split(args, _SQLCMD_VALUES, _SQLCMD_FLAGS)
    if bad is not None:
        return w.impact.not_covered("sqlcmd (option)")
    server = got.get("-S") or got.get("--server")
    where = server.raw if server is not None else "localhost"
    if "-i" in got:
        w.impact.not_understood(inv.text, "the SQL sqlcmd -i reads from a file")
        return
    out = got.get("-o")
    if out is not None:
        _local(w, inv, state, out, OVERWRITE, tool)
    text = got.get("-Q") or got.get("-q") or got.get("--query")
    if text is None:
        w.impact.not_understood(inv.text, "sqlcmd without -Q reads its SQL from stdin")
        return
    term = got.get("-c") or got.get("--batch-terminator")
    _sqlcmd_text(w, inv, text, tool, where, term.value if term is not None and not term.expands else "GO")


# ---------------------------------------------------------------- entry

_TOOLS = {"redis-cli": redis_cli, "mongosh": mongosh, "mongo": mongosh, "dropdb": pg_tool,
          "pg_restore": pg_tool, "pg_dump": pg_tool, "mysqladmin": mysqladmin, "sqlcmd": sqlcmd}


def datastore(w, inv, parsed, state, tool) -> None:
    _TOOLS[tool](w, inv, parsed, state, tool)
