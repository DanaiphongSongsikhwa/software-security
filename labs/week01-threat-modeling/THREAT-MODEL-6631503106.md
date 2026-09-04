# Threat Model - Sample App (Week 01)

## 1. Data-flow diagram

![DFD](img/task1.png)

Here's what happens in the app:

1. `POST /notes` - client sends some data, app stores it, and returns all notes
2. `GET /notes` - app reads everything from the database and sends it back
3. `POST /upload` - client uploads a file, app saves it, and returns where it's saved
4. `GET /files/<name>` - app reads a file and sends it back

## 2. Elements & trust boundaries

| Element | Type | Trust boundary crossed? |
|---|---|---|
| Web client | external entity | yes (Internet to app) |
| Flask app | process | yes (gets untrusted input) |
| SQLite DB (notes.db) | data store | no (internal) |
| uploads/ store | data store | no (internal, but filenames come from users) |
| POST /notes flow | data flow | yes (client to app, crosses Internet) |
| POST /upload flow | data flow | yes (client to app, crosses Internet) |
| GET /files/<name> flow | data flow | yes (client to app, crosses Internet) |

## 3. STRIDE analysis

| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| /notes | anyone can claim to be anyone | no validation, can store anything | no logs, no way to know who wrote what | returns all notes to anyone | no rate limit, can spam POST | no auth, everyone has full access |
| /upload | no auth needed | can write outside uploads/ | no upload logs | leaks saved file path | no file size limit | uploading a .py file could lead to code execution |
| /files/<name> | no auth, anyone can read | kinda safe but user-controlled | no access logs | all files public, no ownership check | can waste bandwidth | might read files outside uploads/ |

## 4. Top 5 risks + mitigation

1. Path traversal in /upload (high/high) - can write anywhere. Fix: use secure_filename(), store outside web root, allow-list extensions.
2. No auth on /notes (high/high) - anyone can read and write. Fix: add login, scope notes to the logged-in user.
3. Info disclosure via GET /notes (high/medium) - returns all notes. Fix: only return notes belonging to the current user.
4. No logging (medium/medium) - can't trace anything. Fix: log every request with timestamp, IP, and action.
5. No size/rate limits (medium/medium) - can DoS by uploading big files or flooding POST. Fix: set max file size and rate limit per IP.
