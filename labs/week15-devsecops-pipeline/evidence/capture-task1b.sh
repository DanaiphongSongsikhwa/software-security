#!/usr/bin/env bash
# Task 1b capture: fail-open (:8090) vs fail-closed (:8091).
# Pass your hosted instance URL as $1 to also show the live personal flag, e.g.:
#   bash evidence/capture-task1b.sh http://10.66.0.1:30000
cd "$(dirname "$0")/.."
docker compose up -d >/dev/null 2>&1
for i in $(seq 1 30); do curl -s -o /dev/null localhost:8090 && curl -s -o /dev/null localhost:8091 && break; sleep 1; done
printf '%s | %s | ' "$(whoami)" '6631503106'; TZ=Asia/Bangkok date '+%F %T %Z'
echo "$ curl -s localhost:8090/admin   (no token -> fail OPEN)"
curl -s localhost:8090/admin; echo
echo "$ curl -s localhost:8091/admin   (no token -> fail CLOSED)"
curl -s localhost:8091/admin; echo
echo "$ curl -s localhost:8091/admin -H 'Authorization: alice-token'  (real admin still works)"
curl -s localhost:8091/admin -H 'Authorization: alice-token'; echo
if [ -n "$1" ]; then
  echo "$ curl -s $1/admin   (my hosted instance -> personal flag)"
  curl -s -m 8 "$1/admin"; echo
fi
