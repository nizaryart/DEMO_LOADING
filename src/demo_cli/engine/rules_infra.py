"""The infrastructure family: terraform / tofu, kubectl, helm, pulumi, cdk,
loaded only when a line names one of them (M2.2b1).

The grammars and the examples live here, as rules_git.py does for git; the
work is in infra_ops.py. A hook call that never meets these tools pays
nothing for either. Every grammar was read from the installed tool and the
facts the examples call VERIFIED were run (see infra_ops.py).
"""
from __future__ import annotations

from typing import Tuple

from .effects import CREATE, DELETE, OVERWRITE, RUN, SERVICE_KEEP, SERVICE_LOSS
from .rules import OptionSpec, Rule, ex

_HERE = "cluster:current/default"
_WORKLOAD = "cluster-workload:current/default"

FAMILY_RULES: Tuple[Rule, ...] = (
    Rule(id="terraform", tools=("terraform", "tofu"), resolver="infra", options=OptionSpec(),
         examples=(
             ex("terraform plan", note="a read"),
             ex("terraform destroy", reaches={"iac:terraform": DELETE}),
             ex("terraform -chdir=infra destroy -auto-approve",
                reaches={"iac:terraform:infra": DELETE},
                note="a global option before the subcommand"),
             ex("terraform apply", reaches={"iac:terraform": OVERWRITE},
                note="ruling 2026-10-06: an apply may replace resources, so it escalates"),
             ex("terraform apply -destroy", reaches={"iac:terraform": DELETE}),
             ex("terraform state rm aws_instance.x", reaches={"iac:terraform": DELETE}),
             ex("terraform workspace delete prod", reaches={"iac:terraform": DELETE}),
             ex("terraform workspace new dev", reaches={"iac:terraform": CREATE},
                note="only adds: allowed and listed"),
             ex("terraform plan -out=a.txt", destroys={"a.txt"},
                note="the plan file is written over a.txt"),
             ex("terraform destroy --help", note="VERIFIED: help anywhere before --"),
             ex("terraform -chdir infra destroy", uncovered={"terraform (option)"},
                note="VERIFIED: -chdir needs '=', terraform refuses the line"),
             ex("terraform test", uncovered={"terraform test"},
                note="it applies for real, then destroys: not claimed"),
             ex("tofu destroy", reaches={"iac:tofu": DELETE}, note="OpenTofu, the same CLI"),
             ex("tofu -chdir infra destroy", reaches={"iac:tofu:infra": DELETE},
                note="VERIFIED: tofu 1.13 takes -chdir without '='"),
         )),
    Rule(id="kubectl", tools=("kubectl",), resolver="infra", options=OptionSpec(),
         examples=(
             ex("kubectl get pods", note="a read"),
             ex("kubectl delete pod x", reaches={_HERE: DELETE}),
             ex("kubectl -n prod delete deploy api", reaches={"cluster:current/prod": DELETE},
                note="a global option before the subcommand"),
             ex("kubectl --context prod delete ns x", reaches={"cluster:prod/default": DELETE}),
             ex("kubectl -n -h delete pod x", reaches={"cluster:current/-h": DELETE},
                note="VERIFIED: -h is the namespace here, not help"),
             ex("kubectl delete pod x --dry-run=client", note="a dry run"),
             ex("kubectl apply -f k8s/", reaches={_HERE: OVERWRITE},
                note="ruling 2026-10-06 (as terraform apply)"),
             ex("kubectl apply --prune --all -f k8s/", reaches={_HERE: DELETE},
                note="--prune deletes what the manifests no longer list"),
             ex("kubectl create deployment api --image=x", reaches={_HERE: CREATE}),
             ex("kubectl create job j --image=x -- rm -rf /data",
                reaches={"cluster:current/default": RUN},
                note="M2.3b (Rb4): the command runs in the cluster, nobody read it - RUN"),
             ex("kubectl scale deploy api --replicas=0", reaches={_WORKLOAD: SERVICE_LOSS}),
             ex("kubectl scale deploy api --replicas=3", reaches={_WORKLOAD: SERVICE_KEEP}),
             ex("kubectl drain node1", reaches={_WORKLOAD: SERVICE_LOSS}),
             ex("kubectl rollout restart deploy/api", reaches={_WORKLOAD: SERVICE_KEEP}),
             ex("kubectl exec app -- rm -rf /data", reaches={_WORKLOAD: RUN},
                note="M2.3b (Rb4, F2): code runs in the pod - RUN, like docker exec"),
         )),
    Rule(id="helm", tools=("helm",), resolver="infra", options=OptionSpec(),
         examples=(
             ex("helm list", note="a read"),
             ex("helm uninstall api", reaches={_HERE: DELETE}),
             ex("helm -n prod uninstall api", reaches={"cluster:current/prod": DELETE},
                note="a global option before the subcommand"),
             ex("helm del api", reaches={_HERE: DELETE}, note="VERIFIED alias"),
             ex("helm upgrade api ./chart", reaches={_HERE: OVERWRITE}),
             ex("helm install api ./chart", reaches={_HERE: CREATE}),
             ex("helm install api ./chart --set k=v", reaches={"cluster:current/default": RUN},
                note="M2.3b (Rb4): values feed templates the engine cannot read - RUN"),
             ex("helm upgrade api ./chart --dry-run=server", note="a dry run"),
             ex("helm test api", uncovered={"helm test"}, note="test pods run code"),
             ex("helm rollback api 1 --dry-run=none", reaches={_HERE: OVERWRITE},
                note="VERIFIED: helm 4 rolls back for real with --dry-run=none"),
             ex("helm rollback api 1 --dry-run", note="a dry run in helm 3 and 4"),
         )),
    Rule(id="pulumi", tools=("pulumi",), resolver="infra", options=OptionSpec(),
         examples=(
             ex("pulumi destroy --yes", reaches={"iac:pulumi": DELETE}),
             ex("pulumi -s dev destroy", reaches={"iac:pulumi:dev": DELETE},
                note="VERIFIED: cobra reads -s before the subcommand"),
             ex("pulumi dn", reaches={"iac:pulumi": DELETE}, note="VERIFIED alias"),
             ex("pulumi up", reaches={"iac:pulumi": OVERWRITE}),
             ex("pulumi stack rm dev", reaches={"iac:pulumi": DELETE}),
             ex("pulumi stack remove dev", reaches={"iac:pulumi": DELETE},
                note="VERIFIED alias (pulumi 3.268)"),
             ex("pulumi state rm urn:x", reaches={"iac:pulumi": DELETE},
                note="VERIFIED alias (pulumi 3.268)"),
             ex("pulumi destroy --preview-only", note="a preview"),
             ex("pulumi whoami", note="a read"),
             ex("pulumi preview", uncovered={"pulumi preview"},
                note="it runs the project's program: M2.3's runner row"),
         )),
    Rule(id="cdk", tools=("cdk",), resolver="infra", options=OptionSpec(),
         examples=(
             ex("cdk destroy", reaches={"iac:cdk": DELETE}),
             ex("cdk --trace true destroy", reaches={"iac:cdk": DELETE},
                note="VERIFIED: yargs gives `true` to --trace"),
             ex("cdk deploy", reaches={"iac:cdk": OVERWRITE}),
             ex("cdk diff", uncovered={"cdk diff"},
                note="it runs the project's app: M2.3's runner row"),
             ex("cdk --foo destroy", uncovered={"cdk (option)"},
                note="VERIFIED: an unknown option eats `destroy`"),
         )),
)
