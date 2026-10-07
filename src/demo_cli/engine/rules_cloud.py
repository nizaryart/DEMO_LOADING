"""The cloud family: aws, s3cmd, rclone and mc, loaded only when a line names
one of them (M2.2b2a).

The grammars and the examples live here, as rules_infra.py does for the
infrastructure CLIs; the work is in cloud_ops.py. Every grammar was read from
the tool's own data (aws v2's command index, rclone's `help flags`, mc's and
s3cmd's --help) and the facts the examples call VERIFIED were run.
"""
from __future__ import annotations

from typing import Tuple

from .effects import CREATE, DELETE, OVERWRITE, SEND
from .rules import OptionSpec, Rule, ex

FAMILY_RULES: Tuple[Rule, ...] = (
    Rule(id="aws", tools=("aws",), resolver="cloud", options=OptionSpec(),
         examples=(
             ex("aws ec2 describe-instances", note="a read"),
             ex("aws iam list-users", note="ruling R3: a read the old rule escalated"),
             ex("aws ec2 terminate-instances --instance-ids i-1",
                reaches={"cloud:aws:ec2": DELETE}),
             ex("aws --prof prod ec2 terminate-instances --instance-ids i-1",
                reaches={"cloud:aws:ec2@prod": DELETE},
                note="VERIFIED: a global option, abbreviated, before the service"),
             ex("aws iam delete-user --user-name x", reaches={"cred:aws:iam": DELETE}),
             ex("aws sqs purge-queue --queue-url q", reaches={"queue:aws:sqs": DELETE}),
             ex("aws sns publish --topic-arn t --message m", reaches={"queue:aws:sns": SEND}),
             ex("aws ec2 terminate-instances --instance-ids i-1 --dry-run",
                note="VERIFIED: simulates, or is refused - nothing runs"),
             ex("aws s3 rm s3://b/x", reaches={"storage:aws:s3://b": DELETE}),
             ex("aws s3 cp a.txt s3://b/", reaches={"storage:aws:s3://b": OVERWRITE},
                note="ruling R2: an upload may replace objects"),
             ex("aws s3 cp a.txt s3://b/ --no-overwrite", reaches={"storage:aws:s3://b": CREATE},
                note="VERIFIED flag (aws 2.37): only adds"),
             ex("aws s3 cp s3://b/a.txt a.txt", destroys={"a.txt"},
                note="a download writes over a local file: captured"),
             ex("aws s3 sync s3://b dir --delete", destroys={"dir/"}),
             ex("aws s3api get-object --bucket b --key k a.txt", destroys={"a.txt"},
                note="an outfile operation writes its local file"),
             ex("aws ec2 run-instances --image-id ami-1", uncovered={"aws ec2 run-instances"},
                note="a creation can carry code (--user-data): not claimed"),
             ex("aws eks update-kubeconfig --name c", uncovered={"aws eks update-kubeconfig"},
                note="a local command that writes tool configuration"),
         )),
    Rule(id="s3cmd", tools=("s3cmd",), resolver="cloud", options=OptionSpec(),
         examples=(
             ex("s3cmd ls s3://b", note="a read"),
             ex("s3cmd del s3://b/x", reaches={"storage:s3cmd:s3://b": DELETE}),
             ex("s3cmd del -n s3://b/x", note="VERIFIED: del honours --dry-run"),
             ex("s3cmd rb -n s3://b", reaches={"storage:s3cmd:s3://b": DELETE},
                note="VERIFIED: rb does NOT honour --dry-run"),
             ex("s3cmd put a.txt s3://b/", reaches={"storage:s3cmd:s3://b": OVERWRITE}),
             ex("s3cmd get --force s3://b/a.txt a.txt", destroys={"a.txt"}),
             ex("s3cmd get s3://b/a.txt a.txt",
                note="VERIFIED: without --force an existing file is skipped"),
         )),
    Rule(id="rclone", tools=("rclone",), resolver="cloud", options=OptionSpec(),
         examples=(
             ex("rclone ls remote:b", note="a read"),
             ex("rclone purge remote:b", reaches={"storage:rclone:remote:": DELETE}),
             ex("rclone sync dir remote:b", reaches={"storage:rclone:remote:": DELETE},
                note="VERIFIED: sync deletes what the source lacks"),
             ex("rclone copy dir remote:b", reaches={"storage:rclone:remote:": OVERWRITE}),
             ex("rclone copy dir remote:b --ignore-existing",
                reaches={"storage:rclone:remote:": CREATE}),
             ex("rclone sync remote:b dir", destroys={"dir/"}),
             ex("rclone --dry-run purge remote:b", note="VERIFIED: nothing is deleted"),
             ex("rclone mount remote:b mnt", uncovered={"rclone mount"}),
         )),
    Rule(id="mc", tools=("mc",), resolver="cloud", options=OptionSpec(),
         examples=(
             ex("mc ls minio/b", note="a read"),
             ex("mc rm --recursive --force minio/b", reaches={"storage:mc:minio": DELETE},
                note="no such local path: an alias"),
             ex("mc rm --recursive --force dir", unknown=True,
                note="VERIFIED: a path that is not an alias is LOCAL; dir exists here"),
             ex("mc rm --recursive --force ./dir", destroys={"dir/"}),
             ex("mc admin info minio", uncovered={"mc admin"}),
         )),
)
