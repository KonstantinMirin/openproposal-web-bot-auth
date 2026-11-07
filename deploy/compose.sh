# Sourced by e2e/run-e2e.sh and deploy/localhost/run.sh: one stack run, from nothing.
#
# compose_run "SERVICES" ARGS...: with the caller's "${compose[@]}", start from
# clean volumes, build, start SERVICES and wait until they are healthy, then run
# `run --rm ARGS...` once. On a failure it prints the services' logs and exits 1.

compose_run() {
    local services=$1
    shift
    # Start from clean volumes, so every run is a fresh stack: no keys, no records.
    "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1
    "${compose[@]}" build
    # shellcheck disable=SC2086  # SERVICES is a list of names
    "${compose[@]}" up --detach --wait $services
    if ! "${compose[@]}" run --rm "$@"; then
        # shellcheck disable=SC2086
        "${compose[@]}" logs --no-color $services | tail -n 200
        exit 1
    fi
}
