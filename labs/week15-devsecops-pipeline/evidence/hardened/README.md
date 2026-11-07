# Prepared files for Task 2-4 (copy into the ROOT of your own PUBLIC repo)

These are the Blue-team fixes verified locally in Week 15. Use them in a
throwaway public repo you own (never the course repo, never a private repo).

## Layout in your repo
    .github/workflows/security-ci.yml   <- evidence/hardened/security-ci.yml (actions pinned to SHAs)
    .gitleaks.toml                      <- evidence/hardened/.gitleaks.toml (path allowlist for docs false positive)
    insecure_service.py, secure_service.py, sample-service.py, docker-compose.yml,
    README.md, README-pipeline.md       <- copies of this lab folder

## One manual edit for Semgrep (host="0.0.0.0")
In insecure_service.py and secure_service.py, add a nosemgrep comment on the
app.run line, e.g.:

    app.run(host="0.0.0.0", port=8090, debug=False)  # nosemgrep: python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host -- 0.0.0.0 is required so Docker can publish the lab port; only the published port is reachable

## Why these changes (Task 3)
- Actions pinned to commit SHAs  -> clears Semgrep github-actions-mutable-action-tag
- nosemgrep on host="0.0.0.0"     -> justified exception, not a blanket ignore
- .gitleaks.toml path allowlist   -> the README curl example is a docs false positive (path-based, survives commits)
- trivy-action pinned to v0.36.0  -> the template's @0.24.0 tag no longer resolves on GitHub

## Task 4 (Red): open ONE PR per planted defect, each hits a different gate step
1. Add  urllib3==1.26.4  to a requirements.txt     -> Trivy SCA gate fails (HIGH CVEs)
2. Add a Dockerfile that runs as root (no USER)    -> Trivy config gate fails (DS-0002 HIGH)
3. Commit a fake token (AWS_SECRET_ACCESS_KEY=AKIA...) -> Gitleaks gate fails
Do NOT use chmod 777 or :latest -- the gate filters HIGH,CRITICAL and lets those through.
