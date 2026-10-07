"""The container family: docker, podman, docker-compose, loaded only when a
line names one of them (M2.2b3). The work is in container_ops.py."""
from __future__ import annotations

from typing import Tuple

from .effects import DELETE, OVERWRITE
from .rules import OptionSpec, Rule, ex

_LOCAL = "container:docker@local"

FAMILY_RULES: Tuple[Rule, ...] = (
    Rule(id="docker", tools=("docker", "podman"), resolver="container", options=OptionSpec(),
         examples=(
             ex("docker ps -a", note="a read"),
             ex("docker rm -f c", reaches={_LOCAL: DELETE}),
             ex("docker container remove c", reaches={_LOCAL: DELETE}, note="VERIFIED alias"),
             ex("docker volume rm v", reaches={_LOCAL: DELETE}),
             ex("docker system prune -af --volumes", reaches={_LOCAL: DELETE}),
             ex("docker --context prod volume rm v", reaches={"container:docker@prod": DELETE},
                note="a global option before the command"),
             ex("docker push myrepo/app", reaches={"container:registry/myrepo/app": OVERWRITE},
                note="ruling R2: a push may replace a registry tag"),
             ex("docker compose down", reaches={_LOCAL: DELETE},
                note="ruling R5: the containers' writable layers go, as with docker rm"),
             ex("docker compose down --dry-run", note="a dry run"),
             ex("docker stop app", uncovered={"docker stop"},
                note="ruling R5: nothing persistent is lost; today's path decides"),
             ex("docker run --rm alpine rm -rf /data", uncovered={"docker run"},
                note="code runs in the container: today's path decides"),
             ex("podman volume rm v", reaches={"container:podman@local": DELETE}),
         )),
    Rule(id="docker-compose", tools=("docker-compose",), resolver="container", options=OptionSpec(),
         examples=(
             ex("docker-compose ps", note="a read"),
             ex("docker-compose down --volumes",
                reaches={"container:docker-compose@local": DELETE}),
             ex("docker-compose up -d", uncovered={"compose up"}),
         )),
)
