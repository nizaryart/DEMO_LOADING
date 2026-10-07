"""The data-store family: redis-cli, mongosh / mongo, dropdb / pg_restore /
pg_dump, mysqladmin, sqlcmd, loaded only when a line names one of them
(M2.2b3). The work is in datastore_ops.py."""
from __future__ import annotations

from typing import Tuple

from .effects import DELETE, OVERWRITE, RUN, SERVICE_LOSS
from .rules import OptionSpec, Rule, ex

FAMILY_RULES: Tuple[Rule, ...] = (
    Rule(id="redis-cli", tools=("redis-cli",), resolver="datastore", options=OptionSpec(),
         examples=(
             ex("redis-cli GET k", note="a read (READONLY in redis's own table)"),
             ex("redis-cli CONFIG GET maxmemory", note="an admin read"),
             ex("redis-cli FLUSHALL", reaches={"flush:redis://localhost": DELETE}),
             ex("redis-cli -h 10.0.0.5 -p 6379 flushdb", reaches={"flush:redis://10.0.0.5": DELETE}),
             ex("redis-cli del key", reaches={"db:redis://localhost": DELETE},
                note="WRITE in redis's own table"),
             ex("redis-cli SET k v", reaches={"db:redis://localhost": OVERWRITE}),
             ex("redis-cli EVAL 'return 1' 0", reaches={"db:redis://localhost": RUN},
                note="an unread Lua script"),
             ex("redis-cli SHUTDOWN", reaches={"db:redis://localhost": SERVICE_LOSS}),
             ex("redis-cli --scan --pattern 'user:*'", note="a read mode"),
             ex("redis-cli --cluster call h:1 FLUSHALL", reaches={"flush:redis://h:1": DELETE},
                note="the command runs on every node of the cluster h:1 belongs to"),
         )),
    Rule(id="mongosh", tools=("mongosh", "mongo"), resolver="datastore", options=OptionSpec(),
         examples=(
             ex("mongosh --eval 'db.dropDatabase()'", reaches={"db:mongodb://localhost": RUN},
                note="unread JavaScript"),
             ex("mongosh --version", note="a read"),
         )),
    Rule(id="pg-tools", tools=("dropdb", "pg_restore", "pg_dump"), resolver="datastore",
         options=OptionSpec(),
         examples=(
             ex("dropdb mydb", reaches={"db:postgres://localhost/mydb": DELETE}),
             ex("dropdb -h db.example.com mydb", reaches={"db:postgres://db.example.com/mydb": DELETE}),
             ex("pg_restore --clean -d mydb dump.sql", reaches={"db:postgres://localhost/mydb": DELETE}),
             ex("pg_restore -d mydb dump.sql", reaches={"db:postgres://localhost/mydb": OVERWRITE}),
             ex("pg_restore -l dump.sql", note="a listing"),
             ex("pg_dump -f a.txt mydb", destroys={"a.txt"}, note="the dump file is written over a.txt"),
         )),
    Rule(id="mysqladmin", tools=("mysqladmin",), resolver="datastore", options=OptionSpec(),
         verified=False,
         examples=(
             ex("mysqladmin -u root drop mydb", reaches={"db:mysql://localhost/mydb": DELETE}),
             ex("mysqladmin shutdown", reaches={"db:mysql://localhost": SERVICE_LOSS}),
             ex("mysqladmin status", uncovered={"mysqladmin status"},
                note="ruling R4: a documentation-only grammar claims nothing that allows"),
         )),
    Rule(id="sqlcmd", tools=("sqlcmd",), resolver="datastore", options=OptionSpec(),
         examples=(
             ex('sqlcmd -S db -Q "DROP TABLE t"', reaches={"db:mssql://db": DELETE}),
             ex('sqlcmd -S db -Q "SELECT 1"', note="a read"),
             ex("sqlcmd delete", reaches={"db:mssql://local-container": DELETE}),
         )),
)
