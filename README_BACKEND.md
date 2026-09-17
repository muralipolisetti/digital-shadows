# SecureApp — Backend & Security Integration

File Integrity Monitoring (FIM) with tamper detection, built with Python,
Flask and SHA-256. Local only, no database, no cloud, standard library plus
Flask.

## What the system claims (and what it does not)

SecureApp **detects** unauthorised modification of a protected file. It does
**not** prevent modification. Anyone with write access can still edit or
delete `protected_data.txt`. What SHA-256 guarantees is that changing even one
byte produces a completely different hash, so the change cannot pass
unnoticed. Say this exact thing to the judges — claiming SHA-256 makes a file
unmodifiable is wrong and they will notice.

## Project structure

```
vulnerable-app/
├── app.py                 Flask routes: dashboard, login, integrity, JSON APIs
├── integrity.py           SHA-256 hashing + baseline comparison (core logic)
├── auth.py                Prototype login (PBKDF2, no plaintext passwords)
├── audit_log.py           Security audit trail -> security.log
├── config.py              Project-base paths and settings
├── create_baseline.py     Manual, confirmed baseline recording
├── create_user.py         Generate a credential block for auth.py
├── protected_data.txt     The monitored file
├── baseline_hash.txt      The trusted SHA-256 reference
├── security.log           Audit trail (created on first run)
├── static/
│   └── style.css
├── templates/
│   ├── index.html         Dashboard
│   ├── integrity.html     Check result page
│   └── login.html         Login form
└── venv/
```

## What each backend file does

**config.py** — computes `BASE_DIR` from its own location, then builds the
absolute paths for `protected_data.txt`, `baseline_hash.txt` and
`security.log`. This is why the app works no matter which folder you start
Flask from. Also holds the Flask secret key and `REQUIRE_AUTH_FOR_API`.

**integrity.py** — the security core.
- `calculate_hash(file_path)` — SHA-256 of a file, read in binary mode in
  64 KB chunks so a large file never loads fully into memory.
- `read_baseline_hash(path)` — reads and validates the baseline (must be 64
  hex characters, tolerates whitespace and a trailing newline).
- `verify_integrity(file_path, expected_hash)` — returns
  `{status, tampered, file, expected_hash, current_hash}`.
- `check_file(file_path, baseline_path)` — the two steps combined; this is
  what Flask calls.
- Raises `IntegrityError` for every expected failure, so Flask can produce a
  clean message instead of a stack trace.
- **It never writes to `baseline_hash.txt`.** If tampering could rewrite the
  baseline, an attacker's version would become the trusted one.

**auth.py** — prototype authentication. The demo account is stored as a
PBKDF2-HMAC-SHA256 hash (200,000 iterations, random salt). Comparison uses
`hmac.compare_digest`. `validate_input()` rejects empty fields. Everything
lives behind `check_credentials()`, so it can be swapped for a real user
store without touching `app.py`.

**audit_log.py** — wraps Python's `logging` module and appends to
`security.log`. Records integrity checks, handled errors, and login attempts
(username and outcome only — the password is never passed into the logging
functions at all).

**app.py** — routes, session handling, error handlers. Every request calls
`run_check()`, which recalculates the hash from disk. Nothing is cached and no
hash is hardcoded, so the result changes the moment the file changes.

## Routes

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Dashboard with live status and recent log entries |
| `/login` | GET, POST | Prototype login |
| `/logout` | GET | Clear the session |
| `/integrity` | GET | Run a check, show the detailed result page (login required) |
| `/api/integrity` | GET | Live check as JSON |
| `/api/security-status` | GET | Security state + timestamp as JSON |

### `/api/integrity`

```json
{
  "status": "SAFE",
  "tampered": false,
  "file": "protected_data.txt",
  "expected_hash": "...",
  "current_hash": "..."
}
```

Tampered case: `"status": "TAMPERING_DETECTED"`, `"tampered": true`.
Error case: HTTP 500 with `{"status": "ERROR", "error": "..."}`.

### `/api/security-status`

```json
{
  "integrity": "SAFE",
  "tampering_detected": false,
  "monitored_file": "protected_data.txt",
  "expected_hash": "...",
  "current_hash": "...",
  "timestamp": "2026-09-17 17:30:00"
}
```

Both APIs are open by default so the frontend teammate can call them while
developing. Set `REQUIRE_AUTH_FOR_API = True` in `config.py` to require a
logged-in session (unauthenticated calls then return HTTP 401 JSON).

## Running it (Windows, Command Prompt)

```bat
cd C:\Users\Murali\vulnerable-app
venv\Scripts\activate
pip install flask
python app.py
```

PowerShell uses `venv\Scripts\Activate.ps1` instead.

Then open:

- http://127.0.0.1:5000/login — sign in (demo: `admin` / `SecureApp@2026`)
- http://127.0.0.1:5000/ — dashboard
- http://127.0.0.1:5000/integrity — detailed check
- http://127.0.0.1:5000/api/integrity — JSON
- http://127.0.0.1:5000/api/security-status — JSON

Stop the server with `Ctrl + C`.

## Demo procedure

### Test 1 — SAFE

1. Make sure `protected_data.txt` holds its original trusted content.
2. If `baseline_hash.txt` is missing or wrong, record it once:
   `python create_baseline.py` and answer `yes`.
3. Open http://127.0.0.1:5000/integrity
4. Expected: 🟢 **Safe**, expected hash == current hash.

### Test 2 — TAMPERING

1. Leave the server running.
2. Open `protected_data.txt` in Notepad, add or remove a character, save.
3. Refresh http://127.0.0.1:5000/integrity
4. Expected: 🔴 **Tampering detected**, the two hashes differ.
5. Open `baseline_hash.txt` — it is unchanged. That is the point.

### Test 3 — RESTORE

1. Undo your edit in Notepad (Ctrl+Z) and save, so the content is byte-for-byte
   the original. Watch for a stray space or an extra newline — those change the
   hash too, which is a good thing to point out in the demo.
2. Refresh http://127.0.0.1:5000/integrity
3. Expected: 🟢 **Safe**.

No Python code is edited at any point in these three tests.

## Inspecting the audit log

Command Prompt:

```bat
type security.log
```

Last 15 lines (PowerShell):

```powershell
Get-Content security.log -Tail 15
```

Live tail while you demo (PowerShell, second window):

```powershell
Get-Content security.log -Wait -Tail 10
```

Only tampering entries:

```bat
findstr TAMPERING_DETECTED security.log
```

Sample lines:

```
2026-09-17 17:30:00 | LOGIN | user=admin | SUCCESS
2026-09-17 17:30:04 | INTEGRITY | protected_data.txt | SAFE | expected=31a9... | current=31a9... | source=dashboard
2026-09-17 17:31:12 | INTEGRITY | protected_data.txt | TAMPERING_DETECTED | expected=31a9... | current=08c5... | source=integrity-page
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| "Baseline file not found" | `baseline_hash.txt` missing → `python create_baseline.py` |
| "Baseline file … does not contain a valid SHA-256 hash" | File is empty or holds text other than a 64-character digest → re-record it |
| "Protected file not found" | `protected_data.txt` was deleted or renamed → restore it |
| Always TAMPERING even after restoring | The content is not byte-identical (trailing newline, different line endings, or Notepad saved as UTF-8 with BOM). Re-type the original exactly, or record a fresh baseline while the file is trusted |
| `ModuleNotFoundError: flask` | The virtual environment is not active, or Flask is not installed → `venv\Scripts\activate` then `pip install flask` |
| Port 5000 already in use | Another app has the port → change `port=5000` at the bottom of `app.py` |
| "Permission denied" reading a file | The file is open and locked by another program → close it |
| A browser cached an old result | Hard refresh with `Ctrl + F5`; the backend never caches |

## Changing the demo account

```bat
python create_user.py
```

Type a username and password (the password is hidden and never saved), then
paste the printed block into the `_USERS` dictionary in `auth.py`.
