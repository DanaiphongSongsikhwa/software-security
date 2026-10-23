# Week 10 work - 6631503106

Branch: `wk10_6631503106`, based on `origin/main`.

- `../../output/pdf/Wk10_6631503106_DRAFT.pdf`: worksheet PDF draft, screenshots pending.
- `export_pdf.py`: regenerate the draft PDF using ReportLab after editing the Markdown.
- `Wk10_6631503106.md`: English worksheet draft, with actual command output.
- `AI_INITIAL_ANSWER.md`: full AI candidate used in the audit.
- `QUIZ_STUDY.md`: answers for revision; not a course-platform submission.
- `evidence/`: real local HTTP transcripts; these are not screenshots.
- `SCREENSHOTS.md`: screenshots still needed before the worksheet is ready to submit.

Run the lab:

```bash
cd /home/danaiphong/software-security/labs/week10-api-security
docker compose -f docker-compose.yml -f docker-compose.defended.yml up -d
```

Ports: 8080 = vulnerable; 8081 = course reference; 8082 = student defense.
The original reference is retained so worksheet commands still behave as specified.
The additional defense uses verified server-side bearer sessions, password hashing,
field/type validation, an ownership check, and the five-attempt rate limit.

Run checks:

```bash
docker compose -f docker-compose.yml -f docker-compose.defended.yml exec -T student-api python -m unittest -v test_defended_api
```

The six regression tests passed on 23 October 2026. Tests cover identity forgery,
ownership/admin access, token expiry, privileged fields/password storage, invalid
bodies/size limits, and rate-limit expiry. Local demo flags are not personal CTF flags.

Remaining: review answers in your own words, add your group if applicable, capture
screenshots, obtain a personal flag only if the instructor requires one, and insert
the final code commit link. Nothing has been submitted to the course platform.

This teaching implementation is not a production API: users, sessions, and rate
limits are in memory and reset on restart. Multi-worker deployments need a shared
store, account/global limits, session revocation, TLS, and stronger abuse controls.
The seeded passwords and unrestricted registration exist only for the local lab.
