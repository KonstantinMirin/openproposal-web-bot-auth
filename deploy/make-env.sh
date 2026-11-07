#!/usr/bin/env bash
# Writes the live deployment's secrets once, with mode 600. Re-running keeps them.
#
#   deploy/make-env.sh [path]    # default: ../../wba-demo.env, next to both checkouts
#
# OPERATOR_KEY: what each agent's own controls require (shared/operator.py), and what the
#   runner sends to them.
# DEMO_BEARER_TOKEN: the token the seller issues its bearer buyer. The seller stores its
#   SHA-256 only; the buyer presents it.
set -euo pipefail
cd "$(dirname "$0")"
target="${1:-../../wba-demo.env}"
umask 077
if [[ -f "$target" ]]; then echo "$target exists; leaving it alone"; exit 0; fi
token() { python3 -c 'import secrets; print(secrets.token_urlsafe(32))'; }
cat > "$target" <<EOF
# Generated $(date -u +%FT%TZ). Secrets of the Web Bot Auth demo; they live only here.
OPERATOR_KEY=$(token)
DEMO_BEARER_TOKEN=$(token)
EOF
echo "wrote $target"
