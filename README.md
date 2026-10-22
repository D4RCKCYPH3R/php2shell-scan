# php2shell-scan

All-in-one scanner for **CVE-2026-109618 / CVE-2026-109619** (php2shell).

Give it a domain and it automatically enumerates subdomains, resolves live hosts, and checks each one for the vulnerability — **without sending crash-inducing probes by default**.

```
python3 scan.py -d example.com
```

```
  php2shell-scan v1.0.0  —  CVE-2026-109618 / CVE-2026-109619

  [crt.sh]       142 hosts
  [HackerTarget]  38 hosts
  [*] 160 unique subdomains found
  [*] Resolving DNS ...
  [*] 95 live hosts  (65 NXDOMAIN)
  [*] Passive / version-only mode (no crash probes)

  [VULNERABLE] https://app.example.com  - PHP: PHP/8.3.14 - Verdict: VULNERABLE
  [VULNERABLE] https://api.example.com  - PHP: PHP/8.4.12 - Verdict: VULNERABLE
  ...

  SCAN SUMMARY
  ============================================================
    Total hosts scanned:   95
    Vulnerable:             4
    Fixed/patched:          2
    No signal:             62
    Inconclusive/errors:   27
```

---

## How it works

The vulnerability affects PHP's multipart body parser (CVE-2026-109618 for mod_php, CVE-2026-109619 for PHP-FPM). A crafted POST with array keys nested 62 levels deep causes PHP to exhaust memory, crashing the request handler.

This tool detects exposure two ways:

| Mode | Method | Risk to target |
|---|---|---|
| **Passive** (default) | Reads `X-Powered-By` header from a 42-byte control request; flags unpatched versions | None — no service impact |
| **Active** (`--active`) | Sends crash-inducing probes up to 29 MiB | Can kill PHP workers on production |

Use passive mode for continuous or wide-scope scanning. Reserve `--active` for a controlled maintenance window or lab environment.

---

## Installation

```bash
git clone https://github.com/D4RCKCYPH3R/php2shell-scan
cd php2shell-scan
pip install -r requirements.txt
```

**Requirements:** Python 3.9+, `h11`, `tqdm`

---

## Usage

### Scan an entire domain (auto subdomain enum)

```bash
python3 scan.py -d example.com
```

### Scan a pre-built URL/host list

```bash
python3 scan.py -l hosts.txt -t 30 -o results.json
```

### Scan a single URL

```bash
python3 scan.py -u https://example.com -v
```

### Active mode — crash probes (use with caution)

```bash
python3 scan.py -d example.com --active --sapi fpm
```

### Custom paths

```bash
python3 scan.py -d example.com --path /wp-login.php --path /xmlrpc.php
python3 scan.py -l hosts.txt --path-file paths.txt
```

### Save results and run quietly

```bash
python3 scan.py -d example.com -q -o results.json --all-results
```

---

## Options

```
Input (one required):
  -d, --domain DOMAIN       Target domain; subdomains enumerated automatically
  -u, --url URL             Single URL or hostname
  -l, --list FILE           File of URLs/hostnames, one per line

Scan behaviour:
  --active                  Send crash-inducing probes (up to 29 MiB per host)
  --sapi {auto,mod_php,fpm} Active-probe verdict rules (default: auto)
  --path PATH               Extra path to test; repeatable
  --path-file FILE          File of paths to test

Network:
  -t, --threads N           Concurrent scan threads (default: 20)
  --dns-threads N           DNS resolution threads during enum (default: 50)
  --timeout N               Per-request timeout in seconds (default: 30)
  -k, --insecure            Disable TLS certificate verification
  -H, --header KEY:VALUE    Custom header; repeatable

Output:
  -o, --output FILE         Save results to JSON
  --all-results             Include all hosts in JSON, not only vulnerable ones
  -v, --verbose             Print verdict reasons and response snippets
  -q, --quiet               Only print vulnerable hosts
  --no-color                Disable colored output
```

---

## Output

Results are printed to the terminal. With `-o`, a JSON file is written:

```json
{
  "tool": "php2shell-scan",
  "version": "1.0.0",
  "scanned_at": "2026-10-22T21:00:00Z",
  "total_results": 13,
  "results": [
    {
      "host": "https://app.example.com/index.php",
      "verdict": "VULNERABLE",
      "powered_by": "PHP/8.3.14",
      "reason": "X-Powered-By reports an unpatched release: PHP/8.3.14",
      ...
    }
  ]
}
```

Exit code `0` = no vulnerable hosts found. Exit code `1` = at least one vulnerable host.

---

## Subdomain enumeration sources

| Source | Method |
|---|---|
| [crt.sh](https://crt.sh) | Certificate transparency logs |
| [HackerTarget](https://hackertarget.com) | Passive DNS |

Both sources are queried in parallel. To skip enumeration and provide your own list, use `-l`.

---

## Fixed PHP versions

| Branch | Vulnerable below | Fixed version |
|---|---|---|
| PHP 8.2 | < 8.2.35 | 8.2.35+ |
| PHP 8.3 | < 8.3.36 | 8.3.36+ |
| PHP 8.4 | < 8.4.27 | 8.4.27+ |
| PHP 8.5 | < 8.5.12 | 8.5.12+ |

---

## Limitations

- **Passive mode** only flags hosts that advertise their PHP version via `X-Powered-By`. Hosts that suppress this header are reported as `NO SIGNAL` — they may still be vulnerable.
- **Active mode** can produce false positives on some configurations where a patched PHP with a very low `memory_limit` returns an empty HTTP 500 that resembles a crash signal.
- Redirects are not followed.

---

## Credits

- **CVE discovery:** [Calif team](https://calif.io/php2shell/) — original php2shell write-up
- **Scanning logic adapted from:** [assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner)
- **Built for exposure assessment at scale** with safe-by-default behaviour
