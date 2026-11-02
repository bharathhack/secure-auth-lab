# Secure Authentication Lab

A small **local-only** authentication service (Python + Flask) built for the
EdVyro Cyber Security internship, Task 3. It runs on `127.0.0.1` only and uses
an in-memory/SQLite store. Do not expose it to a network.

## Run
```bash
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
python -m unittest -v    # run the tests
```

## Endpoints
| Method | Path | Purpose |
|---|---|---|
| POST | `/register` | Create user (validated, hashed) |
| POST | `/login` | Start session |
| GET | `/profile` | Protected route |
| POST | `/logout` | Destroy session |

Try it:
```bash
curl -c jar -X POST localhost:5000/register -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Str0ngPassword1"}'
curl -c jar -b jar -X POST localhost:5000/login -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Str0ngPassword1"}'
curl -b jar localhost:5000/profile
```

## Checklist mapping (task steps)

### 1. Password hashing + server-side validation
- Passwords hashed with **scrypt** (salted, slow) via `werkzeug.security`; plaintext is never stored or logged.
- Server validates every input: username `^[A-Za-z0-9_]{3,20}$`; password 10-128 chars with lower, upper, digit. Client checks are never trusted.
- SQL uses **parameterised queries** (no SQL injection). Request body capped at 4 KB.

### 2. Secure cookies, logout, session expiry
- Cookie flags: `HttpOnly` (no JS access), `SameSite=Lax` (CSRF mitigation), `Secure` toggle for HTTPS.
- Session is signed (tamper-proof); a **fresh session is issued at login** (prevents session fixation).
- `/logout` clears the session server-side.
- Expiry: **15 min absolute** + **5 min idle timeout**.
- Responses send `Cache-Control: no-store`, `X-Content-Type-Options`, `X-Frame-Options`.

### 3. Rate limits + generic errors
- Max **5 failed logins per 60 s** per IP+username, then a **120 s lockout** (HTTP 429 + `Retry-After`). Even the correct password is refused while locked.
- Wrong username and wrong password return the **identical** message and status ("Invalid username or password.", 401), and unknown users still run a dummy hash so timing doesn't reveal which usernames exist. Duplicate registration also returns a generic error.

## Tests (optional portfolio upgrade)
`test_app.py` covers: valid login, cookie flags, weak password / bad username rejection, identical errors for unknown user vs wrong password, brute-force lockout, no-session access, logout invalidation, idle expiry, and tampered cookies.

## Known limitations (honest notes)
- Rate-limit state is in memory (resets on restart); production would use Redis/a DB.
- `SECRET_KEY` is random per start (sessions reset on restart); production should load it from an env var.
- No CSRF tokens, MFA, or password reset; `Secure` cookie requires HTTPS.
