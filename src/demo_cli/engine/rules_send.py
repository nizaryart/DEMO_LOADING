"""The send family: HTTP clients, gh, mail, ssh / scp / sftp and package
publishing, loaded only when a line names one of them (M2.2b4a). The work is
in send_ops.py; curl and wget keep their core rules (rules.py), whose network
side now lives there too."""
from __future__ import annotations

from typing import Tuple

from .effects import DELETE, OVERWRITE, RUN, SEND
from .rules import OptionSpec, Rule, ex

FAMILY_RULES: Tuple[Rule, ...] = (
    Rule(id="httpie", tools=("http", "https", "xh", "xhs"), resolver="send", options=OptionSpec(),
         examples=(
             ex("http GET https://api.x.com/items", note="a read"),
             ex("http DELETE https://api.x.com/items/1", reaches={"http:api.x.com": DELETE}),
             ex("http https://api.x.com/items name=x", reaches={"http:api.x.com": SEND},
                note="a data item: POST"),
             ex("http https://api.x.com/items", reaches={"http:api.x.com": SEND},
                note="VERIFIED: stdin is not a terminal in an agent's shell, so httpie POSTs it"),
             ex("http --ignore-stdin https://api.x.com/items", note="GET"),
             ex("http --ign https://api.x.com/items", note="VERIFIED: argparse abbreviation"),
             ex("http --offline POST https://api.x.com/items", note="built and printed, never sent"),
             ex("xh PUT https://api.x.com/items/1 name=y", reaches={"http:api.x.com": OVERWRITE}),
             ex("xh -I https://api.x.com/items", note="--ignore-stdin: GET"),
         )),
    Rule(id="gh", tools=("gh",), resolver="send", options=OptionSpec(),
         examples=(
             ex("gh pr list", note="a read"),
             ex("gh pr ls", note="VERIFIED alias"),
             ex("gh repo delete org/x --yes", reaches={"github:org/x": DELETE}),
             ex("gh pr merge 1", reaches={"github:current": OVERWRITE}),
             ex("gh pr merge 1 -d", reaches={"github:current": DELETE},
                note="--delete-branch removes the branch"),
             ex("gh api -X DELETE repos/o/r", reaches={"github:current": DELETE}),
             ex("gh api repos/o/r", note="GET"),
             ex("gh api repos/o/r/issues -f title=x", reaches={"github:current": SEND},
                note="VERIFIED: a field switches the method to POST"),
             ex("gh secret set TOKEN -R o/r", reaches={"secret:o/r": OVERWRITE}),
             ex("gh workflow run deploy.yml", reaches={"github:current": RUN}),
             ex("gh pr create --fill", uncovered={"gh pr create"},
                note="a creation: today's path decides"),
         )),
    Rule(id="mail", tools=("mail", "mailx", "sendmail", "swaks"), resolver="send",
         options=OptionSpec(), verified=False,
         examples=(
             ex("mail -s hi a@b.c", reaches={"mail:a@b.c": SEND}),
             ex("sendmail a@b.c", reaches={"mail:sendmail": SEND}),
             ex("mail -f mbox", uncovered={"mail (a mailbox)"},
                note="ruling R4: reading a mailbox is not claimed"),
             ex("swaks --to a@b.c", reaches={"mail:swaks": SEND}),
         )),
    Rule(id="ssh", tools=("ssh", "scp", "sftp"), resolver="send", options=OptionSpec(),
         examples=(
             ex("ssh host 'rm -rf /srv/app'", reaches={"host:host": RUN}),
             ex("ssh -p 2222 deploy@host -v uptime", reaches={"host:host": RUN},
                note="VERIFIED: options are read again after the host"),
             ex("ssh host", uncovered={"ssh (interactive)"}),
             ex("ssh -G host", note="prints the configuration, connects nowhere"),
             ex("scp a.txt host:/etc/app.conf", reaches={"host:host": OVERWRITE}),
             ex("scp host:/etc/app.conf a.txt", destroys={"a.txt"},
                note="a download over a local file: captured"),
         )),
    Rule(id="publish", tools=("npm", "pnpm", "yarn", "cargo", "twine", "gem", "poetry"),
         resolver="send", options=OptionSpec(),
         examples=(
             ex("npm publish", reaches={"registry:npm": SEND}),
             ex("npm pub", reaches={"registry:npm": SEND}, note="VERIFIED: npm's abbreviation"),
             ex("npm publish --dry-run", note="VERIFIED: nothing reaches the registry"),
             ex("npm unpublish pkg@1.0.0", reaches={"registry:npm": DELETE}),
             ex("npm install", uncovered={"npm"}, note="today's path (and its runtime net)"),
             ex("cargo publish", reaches={"registry:crates": SEND}),
             ex("cargo publish -n", note="VERIFIED: --dry-run"),
             ex("cargo yank --version 1.0.0", reaches={"registry:crates": DELETE}),
             ex("twine upload dist/*", reaches={"registry:pypi": SEND}),
             ex("gem push x.gem", reaches={"registry:rubygems": SEND}),
             ex("gem pu x.gem", reaches={"registry:rubygems": SEND},
                note="VERIFIED: a unique prefix"),
             ex("poetry publish --dry-run", note="VERIFIED: nothing is uploaded"),
         )),
)
