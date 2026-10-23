#!/usr/bin/env bash
# Run from any directory. Only the provided local lab is contacted.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
printf '%s | %s | ' "$(whoami)" '6631503106'
TZ=Asia/Bangkok date '+%F %T %Z'
show() { printf '\n$ '; printf '%q ' "$@"; printf '\n'; "$@"; printf '\n'; }
case "${1:-}" in
  0)
    show curl -sS -i http://localhost:8080/
    show curl -sS -i http://localhost:8081/
    printf '\nSeed users from vulnerable_api.py:\nalice | 1 | balance=100 | admin=false\nbob | 2 | balance=50 | admin=false\ncarol | 3 | balance=9999 | admin=true\n'
    ;;
  1)
    show curl -sS -i http://localhost:8080/api/users/3/orders
    show curl -sS -i http://localhost:8080/api/users/2/orders
    show curl -sS -i http://localhost:8081/api/users/3/orders
    show curl -sS -i -H 'X-User-Id: 1' http://localhost:8081/api/users/3/orders
    show curl -sS -i -H 'X-User-Id: 1' http://localhost:8081/api/users/1/orders
    ;;
  2)
    for port in 8080 8081; do
      show curl -sS -i -X POST "http://localhost:$port/api/users" -H 'Content-Type: application/json' -d '{"username":"mallory","password":"x","is_admin":true,"balance":1000000}'
    done
    ;;
  3)
    # For the expected 401x5/429x2, wait at least 60s after prior :8081 logins.
    for pw in wrong1 wrong2 wrong3 alice123; do
      show curl -sS -i -X POST http://localhost:8080/api/login -H 'Content-Type: application/json' -d "{\"username\":\"alice\",\"password\":\"$pw\"}"
    done
    printf '\n$ seven wrong-password attempts to http://localhost:8081/api/login\n'
    for i in $(seq 1 7); do
      curl -sS -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8081/api/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"wrong"}'
    done
    ;;
  5)
    show nl -ba solution_api.py
    ;;
  audit)
    show curl -sS -i -H 'X-User-Id: 3' http://localhost:8081/api/users/3/orders
    show curl -sS -i -H 'X-User-Id: 3' http://localhost:8082/api/users/3/orders
    ;;
  *) printf 'Usage: bash capture_evidence.sh {0|1|2|3|5|audit}\n'; exit 2 ;;
esac
