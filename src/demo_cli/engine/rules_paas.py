"""The PaaS family: heroku, fly, vercel, netlify, wrangler, firebase, loaded
only when a line names one of them (M2.2b4b1). The work is in paas_ops.py."""
from __future__ import annotations

from typing import Tuple

from .effects import DELETE, OVERWRITE
from .rules import OptionSpec, Rule, ex

FAMILY_RULES: Tuple[Rule, ...] = (
    Rule(id="paas", tools=("heroku", "fly", "flyctl", "vercel", "vc", "netlify", "wrangler", "firebase"),
         resolver="paas", options=OptionSpec(),
         examples=(
             ex("heroku apps:destroy myapp --confirm myapp", reaches={"paas:heroku": DELETE}),
             ex("heroku config:set A=1 -a myapp", reaches={"deploy:heroku": OVERWRITE}),
             ex("heroku logs -a myapp", note="a read"),
             ex("heroku apps:create x", uncovered={"heroku apps create"}, note="a creation"),
             ex("fly apps destroy x", reaches={"paas:fly": DELETE}),
             ex("fly apps rm x", reaches={"paas:fly": DELETE}, note="VERIFIED alias"),
             ex("fly destroy x", reaches={"paas:fly": DELETE}, note="VERIFIED hidden command"),
             ex("fly deploy", reaches={"deploy:fly": OVERWRITE}),
             ex("fly secrets unset KEY", reaches={"secret:fly": OVERWRITE}),
             ex("vercel --prod", reaches={"deploy:vercel": OVERWRITE}),
             ex("vercel", uncovered={"vercel deploy (a preview)"}, note="a preview: a creation"),
             ex("vercel rm my-deployment", reaches={"deploy:vercel": DELETE}),
             ex("netlify deploy --prod", reaches={"deploy:netlify": OVERWRITE}),
             ex("netlify deploy", uncovered={"netlify deploy (a draft)"}),
             ex("netlify sites:delete abc", reaches={"paas:netlify": DELETE}),
             ex("wrangler deploy", reaches={"deploy:wrangler": OVERWRITE}),
             ex("wrangler delete", reaches={"paas:wrangler": DELETE}),
             ex("wrangler kv key delete K --remote", reaches={"deploy:wrangler": DELETE}),
             ex("wrangler kv key delete K", unknown=True,
                note="VERIFIED: local by default - M2.3b: a write to wrangler's local state, not read"),
             ex("wrangler kv key get K", note="a read of the local state"),
             ex("wrangler kv:key delete K", unknown=True, note="wrangler 3 syntax: not a wrangler 4 command"),
             ex("firebase deploy", reaches={"deploy:firebase": OVERWRITE}),
             ex("firebase FIRESTORE:DELETE /users", reaches={"deploy:firebase": DELETE},
                note="VERIFIED: matched case-insensitively"),
         )),
)
