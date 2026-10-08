"""The SaaS and migration family: shopify, wp, stripe, rails / rake,
manage.py / django-admin, alembic, prisma, knex, flyway, liquibase, loaded
only when a line names one of them (M2.2b4b2). The work is in saas_ops.py."""
from __future__ import annotations

from typing import Tuple

from .effects import DELETE, OVERWRITE, SEND
from .rules import OptionSpec, Rule, ex

FAMILY_RULES: Tuple[Rule, ...] = (
    Rule(id="saas", tools=("shopify", "wp", "stripe"), resolver="saas", options=OptionSpec(),
         examples=(
             ex("shopify theme push", reaches={"deploy:shopify": OVERWRITE}),
             ex("shopify theme:delete -t 1", reaches={"deploy:shopify": DELETE}, note="VERIFIED: colon form"),
             ex("shopify theme pull", note="a read"),
             ex("wp db reset --yes", reaches={"cms:wp": DELETE}),
             ex("wp search-replace a b", reaches={"cms:wp": OVERWRITE}),
             ex("wp search-replace a b --dry-run", note="a dry run"),
             ex("wp post list", uncovered={"wp post list"}, note="outside the verified list"),
             ex("stripe refunds create --charge ch_1", reaches={"payment:stripe": SEND}),
             ex("stripe customers update cus_1 --email a@b.c", reaches={"http:api.stripe.com": OVERWRITE}),
             ex("stripe customers list", note="GET: a read"),
         )),
    Rule(id="migrations", tools=("rails", "rake", "manage.py", "django-admin", "alembic", "prisma",
                                 "knex", "flyway", "liquibase"), resolver="saas", options=OptionSpec(),
         examples=(
             ex("rails db:drop", reaches={"migration:rails": DELETE}),
             ex("rake db:migrate", reaches={"migration:rails": OVERWRITE}),
             ex("rails db:drop:primary", reaches={"migration:rails": DELETE}, note="a per-database task"),
             ex("rails db:migrate:status", note="a read"),
             ex("django-admin flush --noinput", reaches={"migration:django": DELETE}),
             ex("manage.py migrate", reaches={"migration:django": OVERWRITE}),
             ex("alembic downgrade base", reaches={"migration:alembic": DELETE}),
             ex("alembic upgrade head --sql", note="VERIFIED: offline"),
             ex("prisma migrate reset --force", reaches={"migration:prisma": DELETE}),
             ex("prisma db push --accept-data-loss", reaches={"migration:prisma": DELETE}),
             ex("knex migrate:rollback", reaches={"migration:knex": DELETE}),
             ex("flyway clean migrate", reaches={"migration:flyway": DELETE}, note="the worst operation"),
             ex("liquibase drop-all", reaches={"migration:liquibase": DELETE}),
             ex("liquibase updateSql", note="VERIFIED: prints the SQL"),
         )),
    Rule(id="python-django", tools=("python", "python3", "py"), resolver="saas", options=OptionSpec(),
         examples=(
             ex("python manage.py migrate", reaches={"migration:django": OVERWRITE},
                note="M2.2f: the runner is removed, the Django rule decides"),
             ex("python3 -W ignore ./manage.py flush --no-input", reaches={"migration:django": DELETE}),
             ex("python -m django migrate app 0001", reaches={"migration:django": DELETE},
                note="a target migration may go backward"),
             ex("python manage.py migrate --plan", note="--plan prints"),
             ex("python manage.py runserver", uncovered={"manage.py runserver"}),
             ex("python x.py", uncovered={"python"}, note="code this engine does not read: M2.3"),
             ex("python -c 'import os'", uncovered={"python"}),
         )),
)
