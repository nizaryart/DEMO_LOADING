"""The container family: docker, podman, docker-compose, loaded only when a
line names one of them (M2.2b3). The work is in container_ops.py."""
from __future__ import annotations

from typing import Tuple

from .effects import DELETE, OVERWRITE, RUN
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
             ex("docker run --rm alpine rm -rf /data", reaches={_LOCAL: RUN},
                note="M2.2f, ruling (b): code runs in the container - container_runtime's row"),
             ex("docker exec app sh -c 'rm -rf /data'", reaches={_LOCAL: RUN}),
             ex("docker compose exec web ./manage.py flush", reaches={_LOCAL: RUN}),
             ex("docker run --help", note="help"),
             ex("podman volume rm v", reaches={"container:podman@local": DELETE}),
             # M2.2d, ruling D5
             ex("docker cp evil.sh app:/etc/profile", reaches={_LOCAL: OVERWRITE},
                note="VERIFIED: NAME:PATH is a container"),
             ex("docker cp app:/etc/hosts a.txt", destroys={"a.txt"},
                note="out of a container: a local write, captured"),
             ex("docker container cp app:/x new.txt", creates={"new.txt"}),
             ex("docker cp ./app:x y", note="VERIFIED: a ./ path is local - docker refuses"),
         )),
    Rule(id="docker-compose", tools=("docker-compose",), resolver="container", options=OptionSpec(),
         examples=(
             ex("docker-compose ps", note="a read"),
             ex("docker-compose down --volumes",
                reaches={"container:docker-compose@local": DELETE}),
             ex("docker-compose up -d", uncovered={"compose up"}),
             ex("docker-compose run web pytest", reaches={"container:docker-compose@local": RUN}),
         )),
)
