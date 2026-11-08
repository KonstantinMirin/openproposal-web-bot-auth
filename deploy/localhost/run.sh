#!/usr/bin/env bash
# Rehearses the live deployment on this machine: the production compose file, the production
# Caddyfile snippet, and one run of the live runner, from clean volumes.
#
#   deploy/localhost/run.sh          # run once, check the site serves the report, tear down
#   KEEP=1 deploy/localhost/run.sh   # leave it up; open https://wba-demo.noetis.dev:18443
#                                    # after pointing the four names at 127.0.0.1
set -euo pipefail
source "$(dirname "$0")/../compose.sh"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
gen="$here/generated"
mkdir -p "$gen/run" "$gen/logs"
# The runner writes its reports as UID 10001. The live host creates this directory owned by
# that UID (deploy/README.md, step 4); here the directory belongs to whoever runs the script,
# so it is opened to everyone. Docker Desktop hides the difference; a Linux CI runner doesn't.
chmod 0777 "$gen/run"

# The e2e stack's throwaway CA and its leaf for *.wba-demo.noetis.dev and the apex.
(cd "$repo/e2e" && uv run --project .. python gen_demo_tls.py)
"$repo/deploy/make-env.sh" "$gen/wba-demo.env"

# The production snippet, pointed at the containers and given the throwaway certificate.
python3 "$repo/deploy/local_caddy.py" "$repo/deploy/Caddyfile.snippet" "$gen/Caddyfile"

export WBA_RUN_DIR="$gen/run"
compose=(docker compose --env-file "$gen/wba-demo.env" -f "$repo/deploy/docker-compose.prod.yml"
         -f "$repo/deploy/localhost/docker-compose.localhost.yml" -p wba-demo-rehearsal)
if [[ -z "${KEEP:-}" ]]; then
    trap '"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1' EXIT
fi

compose_run "seller buyer cfbot caddy" -e RUN_INTERVAL=0 runner

# The site serves the report the runner wrote, through the production snippet.
curl --fail --silent --show-error --cacert "$repo/e2e/generated/ca.pem" \
    --resolve wba-demo.noetis.dev:18443:127.0.0.1 \
    https://wba-demo.noetis.dev:18443/latest-run.json \
    | python3 -c 'import json, sys; r = json.load(sys.stdin); print("site serves latest-run.json:", "pass" if r["ok"] else "FAIL"); sys.exit(0 if r["ok"] else 1)'
curl --fail --silent --show-error --output /dev/null --cacert "$repo/e2e/generated/ca.pem" \
    --resolve wba-demo.noetis.dev:18443:127.0.0.1 https://wba-demo.noetis.dev:18443/
for path in buyer.wba-demo.noetis.dev/operator/keys seller.wba-demo.noetis.dev/operator/issue \
            seller.wba-demo.noetis.dev/test/fault cfbot.wba-demo.noetis.dev/run/whoami; do
    host="${path%%/*}"
    status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cacert \
        "$repo/e2e/generated/ca.pem" --resolve "$host:18443:127.0.0.1" -X POST "https://${path/\//:18443/}")
    [[ "$status" == 404 ]] || { echo "https://$path answered $status, not 404"; exit 1; }
done
echo "operator controls are not routed: pass"

# The runner holds no agent's key: no *.jwk is readable in its container, with its own
# mounts, after the agents minted theirs.
keys=$("${compose[@]}" run --rm --no-deps -T --entrypoint sh runner -c \
    'find / -path /proc -prune -o -name "*.jwk" -print 2>/dev/null; true')
[[ -z "$keys" ]] || { echo "the runner can read agent keys:"; echo "$keys"; exit 1; }
echo "the runner holds no agent key: pass"
