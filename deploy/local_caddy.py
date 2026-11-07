"""Rewrites the production Caddy snippet for a local stack: e2e/ and deploy/localhost/.

    python3 deploy/local_caddy.py deploy/Caddyfile.snippet OUT

The upstreams point at the containers instead of the host's ports, the site and
the reports at the front container's mounts, and each site block serves the
e2e stack's throwaway certificate. Everything else, the routing policy
included, is the production snippet unchanged.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

UPSTREAMS = {"18081": "seller", "18082": "buyer", "18083": "cfbot"}
MOUNTS = {
    "/srv/wba-demo/openproposal-web-bot-auth/site": "/srv/site",
    "/srv/wba-demo/run": "/srv/run",
}
SITE_BLOCK = re.compile(r"^([a-z.-]*wba-demo\.noetis\.dev) \{$", re.MULTILINE)


def local(snippet: str) -> str:
    for port, name in UPSTREAMS.items():
        snippet = snippet.replace(f"127.0.0.1:{port}", f"{name}:8000")
    for host_path, mount in MOUNTS.items():
        snippet = snippet.replace(host_path, mount)
    return SITE_BLOCK.sub(r"\1 {\n\ttls /certs/front.pem /certs/front.key", snippet)


if __name__ == "__main__":
    source, out = (Path(arg) for arg in sys.argv[1:3])
    out.write_text(local(source.read_text()))
