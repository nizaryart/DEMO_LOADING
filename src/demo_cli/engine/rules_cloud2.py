"""The second half of the cloud family: gcloud, gsutil, az, azcopy and
railway, loaded only when a line names one of them (M2.2b2b). The work is in
cloud2_ops.py; every grammar was read from the tool's own data and the facts
the examples call VERIFIED were run (never against a real endpoint).
"""
from __future__ import annotations

from typing import Tuple

from .effects import CREATE, DELETE, OVERWRITE, SEND, SERVICE_KEEP
from .rules import OptionSpec, Rule, ex

FAMILY_RULES: Tuple[Rule, ...] = (
    Rule(id="gcloud", tools=("gcloud",), resolver="cloud2", options=OptionSpec(),
         examples=(
             ex("gcloud compute instances list", note="a read"),
             ex("gcloud compute instances delete vm1 --zone z",
                reaches={"cloud:gcloud:compute": DELETE}),
             ex("gcloud --project p compute instances delete vm1",
                reaches={"cloud:gcloud:compute": DELETE}, note="a global flag before the group"),
             ex("gcloud iam roles list", note="ruling R3: a read the old rule escalated"),
             ex("gcloud iam service-accounts delete sa", reaches={"cred:gcloud:iam": DELETE}),
             ex("gcloud compute os-config patch-deployments list",
                note="VERIFIED: patch-deployments is a group, the verb is list"),
             ex("gcloud storage rm gs://b/x", reaches={"storage:gcloud:gs://b": DELETE}),
             ex("gcloud storage cp a.txt gs://b/", reaches={"storage:gcloud:gs://b": OVERWRITE}),
             ex("gcloud storage cp -n a.txt gs://b/", reaches={"storage:gcloud:gs://b": CREATE},
                note="VERIFIED: -n is no-clobber"),
             ex("gcloud storage cp gs://b/a.txt a.txt", destroys={"a.txt"}),
             ex("gcloud compute instances create vm1",
                uncovered={"gcloud compute (verb not listed)"},
                note="a creation can carry a startup script: not claimed"),
             ex("gcloud container clusters get-credentials c",
                uncovered={"gcloud get-credentials"}, note="writes the kube config"),
         )),
    Rule(id="gsutil", tools=("gsutil",), resolver="cloud2", options=OptionSpec(),
         examples=(
             ex("gsutil ls gs://b", note="a read"),
             ex("gsutil rm -r gs://b/x", reaches={"storage:gsutil:gs://b": DELETE}),
             ex("gsutil -m del gs://b/x", reaches={"storage:gsutil:gs://b": DELETE},
                note="VERIFIED alias"),
             ex("gsutil rsync -d dir gs://b", reaches={"storage:gsutil:gs://b": DELETE}),
             ex("gsutil rsync -n -d dir gs://b", note="VERIFIED: rsync -n is a dry run"),
             ex("gsutil cp -n a.txt gs://b/", reaches={"storage:gsutil:gs://b": CREATE},
                note="VERIFIED: cp -n is no-clobber"),
             ex("gsutil cp gs://b/a.txt a.txt", destroys={"a.txt"}),
             ex("gsutil acl get gs://b", note="a read"),
         )),
    Rule(id="az", tools=("az",), resolver="cloud2", options=OptionSpec(),
         examples=(
             ex("az group list", note="a read"),
             ex("az group delete -n rg --yes", reaches={"cloud:az:group": DELETE}),
             ex("az role assignment list", note="ruling R3: a read the old rule escalated"),
             ex("az rest --method delete --url https://management.azure.com/x",
                reaches={"cloud:az:rest": DELETE}),
             ex("az storage blob delete -c c -n x", reaches={"storage:az:storage": DELETE}),
             ex("az storage blob upload -c c -f a.txt -n a.txt",
                reaches={"storage:az:storage": CREATE},
                note="VERIFIED: refuses an existing blob unless --overwrite"),
             ex("az storage blob upload -c c -f a.txt -n a.txt --overwrite",
                reaches={"storage:az:storage": OVERWRITE}),
             ex("az storage blob download -c c -n x -f a.txt", destroys={"a.txt"},
                note="VERIFIED: overwrites a local file by default"),
             ex("az vm create -n vm1 -g rg", uncovered={"az vm create"}),
             ex("az login", uncovered={"az login"}),
         )),
    Rule(id="azcopy", tools=("azcopy",), resolver="cloud2", options=OptionSpec(),
         examples=(
             ex("azcopy list https://a.blob.core.windows.net/c", note="a read"),
             ex("azcopy remove https://a.blob.core.windows.net/c --recursive",
                reaches={"storage:azcopy:a.blob.core.windows.net": DELETE}),
             ex("azcopy rm https://a.blob.core.windows.net/c/x",
                reaches={"storage:azcopy:a.blob.core.windows.net": DELETE}, note="VERIFIED alias"),
             ex("azcopy copy a.txt https://a.blob.core.windows.net/c/",
                reaches={"storage:azcopy:a.blob.core.windows.net": OVERWRITE},
                note="VERIFIED: --overwrite defaults to true"),
             ex("azcopy copy a.txt https://a.blob.core.windows.net/c/ --overwrite=false",
                reaches={"storage:azcopy:a.blob.core.windows.net": CREATE}),
             ex("azcopy sync dir https://a.blob.core.windows.net/c --delete-destination=true",
                reaches={"storage:azcopy:a.blob.core.windows.net": DELETE}),
             ex("azcopy copy https://a.blob.core.windows.net/c/a.txt a.txt", destroys={"a.txt"}),
             ex("azcopy remove https://a.blob.core.windows.net/c --dry-run", note="a dry run"),
         )),
    Rule(id="railway", tools=("railway",), resolver="cloud2", options=OptionSpec(),
         examples=(
             ex("railway status", note="a read"),
             ex("railway volume delete v", reaches={"volume:railway:volume": DELETE}),
             ex("railway down", reaches={"cloud:railway:down": DELETE}),
             ex("railway variable set K=V", reaches={"secret:railway:variable": OVERWRITE}),
             ex("railway up", reaches={"cloud:railway:up": OVERWRITE}),
             ex("railway restart", reaches={"cloud:railway:restart": SERVICE_KEEP}),
             ex("railway run python manage.py migrate", unknown=True,
                note="M2.3b: a command with the platform's environment - not understood"),
         )),
)
