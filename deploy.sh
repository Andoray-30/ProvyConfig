#!/bin/sh
# Operates only this Compose project; no host installs, DNS or firewall changes.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
command_name=${1:-help}
case "$command_name" in
  init)
    if [ -e config.yaml ]; then
      echo 'config.yaml already exists; not overwritten.'
      exit 1
    fi
    install -m 600 config.example.yaml config.yaml
    mkdir -p certs
    echo 'Created private config.yaml. Edit subscriptions, two new domains and ACME email.'
    ;;
  start|test)
    test -f config.yaml || { echo 'Run ./deploy.sh init first.'; exit 1; }
    docker compose build dispatch
    docker compose run --rm --no-deps dispatch prepare
    deploy_mode=$(docker compose run --rm --no-deps --entrypoint python3 dispatch -B -c \
      'import sys;sys.path.insert(0,"app");from portable import config;print(config("/config/config.yaml")["mode"])')
    if [ "$command_name" = start ]; then
      test "$deploy_mode" = relay || { echo 'start requires mode: relay; use test for local-test.'; exit 1; }
      docker compose --profile relay up -d
    else
      test "$deploy_mode" = local-test || { echo 'test requires mode: local-test.'; exit 1; }
      docker compose --profile relay stop caddy
      docker compose up -d dispatch
    fi
    echo 'Started this package. Initial qualification is pending; check status/logs.'
    ;;
  check) docker compose run --rm --no-deps dispatch check ;;
  status) docker compose exec dispatch python3 -B app/portable.py status ;;
  benchmark) docker compose exec dispatch python3 -B app/portable.py benchmark --country "${2:-JP}" --repeats "${3:-3}" ;;
  refresh-rules) docker compose exec dispatch python3 -B app/portable.py refresh-rules ;;
  logs) docker compose --profile relay logs --tail 30 dispatch caddy ;;
  stop) docker compose --profile relay down ;;
  *) echo 'Usage: ./deploy.sh init|start|test|check|status|benchmark [JP 3]|refresh-rules|logs|stop' ;;
esac
