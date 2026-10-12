"""Turn a capture you are allowed to read into a Contour model.

Plain HTTP is read. TLS is named (SNI) and left closed. Secrets are removed
before anything is written.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from contour.redact import looks_live_secret, redact_text

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_ID = re.compile(r"^(?:\d+|[0-9a-fA-F-]{8,}|[A-Za-z]+_[A-Za-z0-9]{2,})$")


def analyze_path(path: Path) -> dict:
    raw = path.read_bytes()
    if raw[:1] in (b"{", b"[") or path.suffix.lower() == ".har":
        return analyze_har(json.loads(raw.decode("utf-8")))
    return analyze_pcap(path)


def analyze_har(har: dict) -> dict:
    entries = ((har.get("log") or {}).get("entries")) or []
    requests: list[dict] = []
    for entry in entries:
        req = entry.get("request") or {}
        method = str(req.get("method") or "").upper()
        url = str(req.get("url") or "")
        if method not in METHODS or not url:
            continue
        parts = urlsplit(url)
        headers = {str(h.get("name", "")).lower(): str(h.get("value", "")) for h in req.get("headers") or []}
        requests.append(
            {
                "method": method,
                "host": parts.hostname or headers.get("host", ""),
                "path": _clean_path(parts.path or "/"),
                "query": _query_names(parts.query),
                "auth": _auth(headers),
                "status": (entry.get("response") or {}).get("status"),
            }
        )
    return _model("har", packets=len(entries), requests=requests, tls=[], redacted=_count_secrets(json.dumps(har)))


def analyze_pcap(path: Path) -> dict:
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw
    from scapy.utils import rdpcap

    packets = rdpcap(str(path))
    requests: list[dict] = []
    tls: list[dict] = []
    for pkt in packets:
        if IP not in pkt or TCP not in pkt or Raw not in pkt:
            continue
        payload = bytes(pkt[Raw].load)
        http = _parse_http(payload)
        if http and http["kind"] == "request":
            requests.append(http)
            continue
        sni = _sni(payload)
        if sni:
            tls.append({"sni": sni, "port": int(pkt[TCP].dport)})
    return _model("pcap", packets=len(packets), requests=requests, tls=tls, redacted=0)


def _parse_http(payload: bytes) -> dict | None:
    head = payload.split(b"\r\n\r\n", 1)[0][:8192]
    try:
        text = head.decode("iso-8859-1")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    parts = lines[0].split(" ")
    if len(parts) < 2 or parts[0] not in METHODS or not parts[1].startswith("/"):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    target = parts[1]
    path, _, query = target.partition("?")
    return {
        "kind": "request",
        "method": parts[0],
        "host": headers.get("host", "").split(":")[0],
        "path": _clean_path(path),
        "query": _query_names(query),
        "auth": _auth(headers),
        "status": None,
    }


def _sni(payload: bytes) -> str | None:
    if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
        return None
    i = 43
    if i >= len(payload):
        return None
    i += 1 + payload[i]
    if i + 2 > len(payload):
        return None
    i += 2 + int.from_bytes(payload[i : i + 2], "big")
    if i >= len(payload):
        return None
    i += 1 + payload[i]
    if i + 2 > len(payload):
        return None
    ext_len = int.from_bytes(payload[i : i + 2], "big")
    i += 2
    end = min(len(payload), i + ext_len)
    while i + 4 <= end:
        etype = int.from_bytes(payload[i : i + 2], "big")
        elen = int.from_bytes(payload[i + 2 : i + 4], "big")
        i += 4
        if etype == 0 and elen >= 5 and i + elen <= len(payload):
            j = i + 3
            nlen = int.from_bytes(payload[j : j + 2], "big")
            name = payload[j + 2 : j + 2 + nlen]
            try:
                return name.decode("ascii")
            except UnicodeDecodeError:
                return None
        i += elen
    return None


def _auth(headers: dict[str, str]) -> str:
    if "authorization" in headers:
        return "bearer"
    if "cookie" in headers:
        return "cookie"
    return "none"


def _query_names(query: str) -> list[str]:
    names = []
    for part in query.split("&"):
        if not part:
            continue
        name = part.split("=", 1)[0]
        if name and not looks_live_secret(name):
            names.append(name[:64])
    return names


def _clean_path(path: str) -> str:
    if looks_live_secret(path):
        return "/«redacted»"
    out = []
    for part in path.split("/"):
        out.append("{id}" if part and _ID.match(part) else part)
    cleaned = "/".join(out)
    return cleaned or "/"


def _count_secrets(blob: str) -> int:
    return len(re.findall(r"sk_(?:live|test)_|Bearer\s+[A-Za-z0-9._\-]{12,}", blob, flags=re.I))


def _model(source: str, packets: int, requests: list[dict], tls: list[dict], redacted: int) -> dict:
    counts: Counter[tuple] = Counter()
    statuses: dict[tuple, set] = {}
    queries: dict[tuple, set] = {}
    auth: dict[tuple, str] = {}
    for req in requests:
        key = (req["method"], req["host"], req["path"])
        counts[key] += 1
        statuses.setdefault(key, set())
        if isinstance(req.get("status"), int):
            statuses[key].add(req["status"])
        queries.setdefault(key, set()).update(req.get("query") or [])
        auth[key] = req.get("auth") or "none"
    endpoints = [
        {
            "method": method,
            "host": host,
            "path": path,
            "count": counts[(method, host, path)],
            "statuses": sorted(statuses.get((method, host, path), [])),
            "query": sorted(queries.get((method, host, path), [])),
            "auth": auth.get((method, host, path), "none"),
        }
        for method, host, path in counts
    ]
    tls_hosts = Counter((row["sni"], row["port"]) for row in tls)
    tls_out = [{"sni": sni, "port": port, "count": n} for (sni, port), n in tls_hosts.most_common()]
    gaps = []
    if tls_out:
        gaps.append(
            "Une partie du flux est TLS. Les corps ne sont pas lus. "
            "Un HAR exporté de ta propre session donne ces corps. Contour ne déchiffre pas le TLS."
        )
    if not endpoints and not tls_out:
        gaps.append("Aucun HTTP en clair, ni SNI. Le fichier ne contient pas un flux applicatif lisible.")
    blob = json.dumps({"endpoints": endpoints, "tls": tls_out})
    if looks_live_secret(blob):
        gaps.append("Un secret a survécu au filtre. Le modèle n'est pas publiable.")
    return {
        "contour": "1",
        "meta": {
            "source": source,
            "tool": "contour-cli",
            "version": "0.2.0",
            "legal": {
                "basis": "own-capture",
                "secretsRedacted": True,
                "drmCircumvention": False,
                "note": "Observation d'une capture que tu as le droit de lire. Pas un décompilateur.",
            },
        },
        "stats": {
            "packets": packets,
            "httpRequests": len(requests),
            "endpoints": len(endpoints),
            "tlsFlows": sum(row["count"] for row in tls_out),
            "secretsSeenInSource": redacted,
        },
        "endpoints": endpoints,
        "tls": tls_out,
        "gaps": gaps,
        "openapi": _openapi(endpoints),
    }


def _openapi(endpoints: list[dict]) -> dict:
    paths: dict[str, dict] = {}
    hosts = []
    for ep in endpoints:
        if ep["host"] and ep["host"] not in hosts:
            hosts.append(ep["host"])
        item = paths.setdefault(ep["path"], {})
        item[ep["method"].lower()] = {
            "parameters": [{"name": name, "in": "query", "schema": {"type": "string"}} for name in ep["query"]],
            "responses": {str(code): {"description": "observé"} for code in (ep["statuses"] or [200])},
        }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": hosts[0] if hosts else "capture",
            "version": "0.0.0-contour",
            "description": "Observé par Contour. Ce n'est pas le code source.",
        },
        "servers": [{"url": f"https://{host}"} for host in hosts] or [{"url": "https://api.example.com"}],
        "paths": paths,
    }
