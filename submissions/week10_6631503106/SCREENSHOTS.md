# Screenshots to capture

The worksheet requires real screenshots, with identity and the evidence visible
in the same image. No screenshots have been created or claimed by the assistant.

Open a terminal and run:

```bash
cd /home/danaiphong/software-security/labs/week10-api-security
bash capture_evidence.sh 0
```

Capture the terminal including the identity stamp. Save as `evidence/task-0.png`.
Repeat with the arguments below. Maximize the terminal and reduce the font slightly
if necessary; if output needs multiple images, run the identity command again so
each image contains identity plus evidence. Do not cut off the commands or results.

| Argument | Save as | Required content |
| --- | --- | --- |
| `0` | `task-0.png` | Both root responses and seeded users |
| `1` | `task-1a.png`, `task-1b.png` | Carol/Bob leak and reference 401/403/200 |
| `2` | `task-2.png` | Both creation responses, privileged fields compared |
| `3` | `task-3a.png`, `task-3b.png` | Vulnerable guesses and reference 401x5,429x2 |
| `5` | `task-5.png` (more if needed) | Reference ownership, allow-list, and limiter lines |
| `audit` | `task-audit.png` | Forged header: reference 200, student defense 401 |

Before Task 3, wait at least 60 seconds after earlier reference login requests.
Restarting the reference container also resets its in-memory rate counter:

```bash
docker compose restart solution-api
bash capture_evidence.sh 3
```

The identity command, if you need to repeat it:

```bash
printf '%s | %s | ' "$(whoami)" '6631503106'; TZ=Asia/Bangkok date '+%F %T %Z'
```

If capturing a browser, put the identity terminal beside it and capture the whole
screen. Use the actual student identity; do not edit a stamp into an image later.
Task 4 is optional and not attempted; there is no bonus screenshot or personal flag.
After capturing, insert the images into the worksheet and export the final PDF.
