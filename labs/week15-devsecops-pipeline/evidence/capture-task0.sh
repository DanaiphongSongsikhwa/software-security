#!/usr/bin/env bash
# Task 0 capture: run sample-service.py and show the three security log lines.
cd "$(dirname "$0")/.."
printf '%s | %s | ' "$(whoami)" '6631503106'; TZ=Asia/Bangkok date '+%F %T %Z'
docker run --rm -v "$PWD:/lab" -w /lab python:3.12-slim bash -c '
pip install -q flask
python sample-service.py >/tmp/s.log 2>&1 &
sleep 3
python - <<PY
import urllib.request, urllib.error
def r(p, m="GET", h={}, d=None):
    q = urllib.request.Request("http://127.0.0.1:5001"+p, method=m, headers=h, data=d)
    try:
        x = urllib.request.urlopen(q); print(x.status, x.read().decode().strip())
    except urllib.error.HTTPError as e:
        print(e.code, e.read().decode().strip())
print("$ POST /login  {token: nope}")
r("/login","POST",{"Content-Type":"application/json"},b"{\"token\":\"nope\"}")
print("$ GET /admin   Authorization: bob-token")
r("/admin", h={"Authorization":"bob-token"})
print("$ GET /admin   Authorization: alice-token")
r("/admin", h={"Authorization":"alice-token"})
PY
echo "--- security event log ---"
grep logger=security /tmp/s.log'
