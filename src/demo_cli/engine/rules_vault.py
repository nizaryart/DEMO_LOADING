"""The vault family (M2.2f): the HashiCorp Vault CLI, loaded only when a line
names it. The work is in vault_ops.py."""
from __future__ import annotations

from typing import Tuple

from .effects import DELETE, OVERWRITE, SERVICE_LOSS
from .rules import OptionSpec, Rule, ex

_V = "secret:vault@default"

FAMILY_RULES: Tuple[Rule, ...] = (
    Rule(id="vault", tools=("vault",), resolver="vault", options=OptionSpec(),
         examples=(
             ex("vault kv get secret/x", note="a read"),
             ex("vault kv put secret/app pw=x", reaches={_V: OVERWRITE}),
             ex("vault kv delete secret/x", reaches={_V: DELETE},
                note="the inventory row the old rule caught"),
             ex("vault kv metadata delete secret/x", reaches={_V: DELETE},
                note="the longest known command: kv metadata delete"),
             ex("vault write -address=https://v.example sys/x a=1",
                reaches={"secret:vault@https://v.example": OVERWRITE}),
             ex("vault kv put -output-curl-string secret/x a=1",
                note="VERIFIED: prints a curl command instead of sending"),
             ex("vault token revoke abc", reaches={"cred:vault@default": DELETE}),
             ex("vault operator seal", reaches={_V: SERVICE_LOSS}),
             ex("vault secrets disable kv/", reaches={_V: DELETE}),
             ex("vault server -dev", uncovered={"vault server"}, note="a server: not claimed"),
             ex("vault frobnicate", uncovered={"vault"}, note="not in the CLI's own table"),
         )),
)
