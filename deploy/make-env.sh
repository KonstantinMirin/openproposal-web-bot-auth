#!/usr/bin/env bash
# Writes the live deployment's secrets once, with mode 600. Re-running keeps them.
#
#   deploy/make-env.sh [path]    # default: ../../wba-demo.env, next to the checkout
#
# SELLER_OPERATOR_KEY, BUYER_OPERATOR_KEY, CFBOT_OPERATOR_KEY: what each agent's own
#   controls require (transport/operator.py), one distinct key per party. The compose files
#   hand each agent its own as OPERATOR_KEY, and the runner the seller's and the buyer's.
# DEMO_BEARER_TOKEN: the token the seller issues its buyer, a second credential of the same
#   principal as the buyer's origin. The seller stores its SHA-256 only; the buyer presents it.
set -euo pipefail
cd "$(dirname "$0")"
target="${1:-../../wba-demo.env}"
umask 077
if [[ -f "$target" ]]; then echo "$target exists; leaving it alone"; exit 0; fi
token() { python3 -c 'import secrets; print(secrets.token_urlsafe(32))'; }
cat > "$target" <<EOF
# Generated $(date -u +%FT%TZ). Secrets of the Web Bot Auth demo; they live only here.
SELLER_OPERATOR_KEY=$(token)
BUYER_OPERATOR_KEY=$(token)
CFBOT_OPERATOR_KEY=$(token)
DEMO_BEARER_TOKEN=$(token)
EOF
echo "wrote $target"
