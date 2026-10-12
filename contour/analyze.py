"""Turn a capture you are allowed to read into a Contour model.

Plain HTTP is read. TLS is named (SNI) and left closed. Body *values* never
enter the model: only structure does (keys, types, status codes).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from contour import __version__
from contour.redact import count_secrets, looks_live_secret

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
# An id-like path segment: digits, a hex/uuid run with a digit in it, or a
# prefixed id such as cus_123 or pi_3Mt9x. The suffix must hold a digit, so
# words like /payment_methods stay words.
_ID = re.compile(r"^(?:\d+|(?=[0-9a-fA-F-]*\d)[0-9a-fA-F-]{8,}|[A-Za-z]{1,6}_(?!v\d+$)(?=\w*\d)\w+)$")
_STATIC = re.compile(r"\.(?:m?js|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|mp4|webm|mp3|wav)$", re.I)
_PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}


def analyze_path(path: Path, host: str | None = None) -> dict:
    raw = path.read_bytes()
    if raw[:4] in _PCAP_MAGIC:
        return analyze_pcap(path, host)
    try:
        har = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError(f"{path} is neither a HAR (JSON) nor a PCAP/PCAPNG file") from None
    return analyze_har(har, host)


def analyze_har(har: dict, host: str | None = None) -> dict:
    log = har.get("log") if isinstance(har, dict) else None
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise ValueError("this JSON is not a HAR file (no log.entries)")
    entries = log["entries"]
    requests: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") or {}
        res = entry.get("response") or {}
        method = str(req.get("method") or "").upper()
        parts = urlsplit(str(req.get("url") or ""))
        if method not in METHODS or parts.scheme not in ("http", "https"):
            continue
        headers = {str(h.get("name", "")).lower(): str(h.get("value", "")) for h in req.get("headers") or []}
        content = res.get("content") or {}
        status = res.get("status")
        requests.append(
            {
                "method": method,
                "host": parts.hostname or headers.get("host", ""),
                "path": _clean_path(parts.path or "/"),
                "query": _query_names(parts.query),
                "auth": _auth(headers),
                # Chrome writes status 0 for blocked or aborted requests.
                "status": status if isinstance(status, int) and status > 0 else None,
                "req_body": _json_body((req.get("postData") or {}).get("text")),
                "res_body": [] if content.get("encoding") == "base64" else _json_body(content.get("text")),
            }
        )
    return _model("har", len(entries), requests, tls=[], secrets=count_secrets(json.dumps(har)), host=host)


def analyze_pcap(path: Path, host: str | None = None) -> dict:
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw
        from scapy.utils import rdpcap
    except ImportError:
        raise ImportError("PCAP support needs scapy: pip install scapy (or pip install '.[pcap]')") from None

    packets = rdpcap(str(path))
    requests: list[dict] = []
    tls: list[dict] = []
    secrets = 0
    for pkt in packets:
        if IP not in pkt or TCP not in pkt or Raw not in pkt:
            continue
        payload = bytes(pkt[Raw].load)
        http = _parse_http(payload)
        if http:
            requests.append(http)
            secrets += count_secrets(payload[:8192].decode("iso-8859-1"))
            continue
        sni = _sni(payload)
        if sni:
            tls.append({"sni": sni, "port": int(pkt[TCP].dport)})
    return _model("pcap", len(packets), requests, tls=tls, secrets=secrets, host=host)


def _parse_http(payload: bytes) -> dict | None:
    head = payload.split(b"\r\n\r\n", 1)[0][:8192].decode("iso-8859-1")
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2 or parts[0] not in METHODS or not parts[1].startswith("/"):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    path, _, query = parts[1].partition("?")
    return {
        "method": parts[0],
        "host": headers.get("host", "").split(":")[0],
        "path": _clean_path(path),
        "query": _query_names(query),
        "auth": _auth(headers),
        "status": None,
        "req_body": [],
        "res_body": [],
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
        name = unquote(part.split("=", 1)[0])
        if name and not looks_live_secret(name):
            names.append(name[:64])
    return names


def _clean_path(path: str) -> str:
    if looks_live_secret(unquote(path)):
        return "/«redacted»"
    out, n = [], 0
    for part in path.split("/"):
        if part and _ID.match(part):
            n += 1
            part = "{id}" if n == 1 else f"{{id{n}}}"
        out.append(part)
    return "/".join(out) or "/"


def _json_body(text: object) -> list:
    """[value] when text is JSON, [] otherwise (JSON null is a real value)."""
    if not isinstance(text, str) or not text.strip():
        return []
    try:
        return [json.loads(text)]
    except ValueError:
        return []


def _kind(value: object) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def _schema(values: list, dropped: list, depth: int = 0) -> dict | None:
    """JSON Schema of the observed values. Structure only, never a value."""
    if not values:
        return None
    present = [v for v in values if v is not None]
    if not present:
        return {"type": "null"}
    if depth > 8:
        return {}
    kinds = {_kind(v) for v in present}
    if kinds == {"integer", "number"}:
        kinds = {"number"}
    if len(kinds) > 1:
        return {}  # mixed types: leave it open rather than guess
    kind = kinds.pop()
    if kind == "object":
        keys = list(dict.fromkeys(k for v in present for k in v))
        dropped.extend(k for k in keys if looks_live_secret(k))
        keys = [k for k in keys if not looks_live_secret(k)]
        if keys and all(_ID.match(k) for k in keys):
            # A map keyed by ids: the keys are data, not fields.
            out = {"type": "object", "additionalProperties": _schema([x for v in present for x in v.values()], dropped, depth + 1) or {}}
        else:
            out = {"type": "object", "properties": {k: _schema([v[k] for v in present if k in v], dropped, depth + 1) for k in keys}}
            required = [k for k in keys if all(k in v for v in present)]
            if required:
                out["required"] = required
    elif kind == "array":
        out = {"type": "array", "items": _schema([x for v in present for x in v], dropped, depth + 1) or {}}
    else:
        out = {"type": kind}
    if len(present) < len(values):
        out["type"] = [out["type"], "null"]
    return out


def confidence(seen: int) -> float:
    """Each extra observation halves the remaining doubt. Evidence, not proof."""
    return min(0.99, round(1 - 0.5**seen, 2))


def _model(source: str, records: int, requests: list[dict], tls: list[dict], secrets: int, host: str | None) -> dict:
    groups: dict[tuple, list[dict]] = {}
    skipped = 0
    for req in requests:
        if host and req["host"] != host and not req["host"].endswith("." + host):
            continue
        if _STATIC.search(req["path"]):
            skipped += 1
            continue
        groups.setdefault((req["method"], req["host"], req["path"]), []).append(req)

    dropped: list[str] = []
    endpoints = []
    for (method, ep_host, path), reqs in sorted(groups.items(), key=lambda kv: (kv[0][1], kv[0][2], kv[0][0])):
        by_status: dict[int, list] = {}
        for r in reqs:
            if r["status"] is not None:
                by_status.setdefault(r["status"], []).extend(r["res_body"])
        auths = {r["auth"] for r in reqs}
        endpoints.append(
            {
                "method": method,
                "host": ep_host,
                "path": path,
                "count": len(reqs),
                "confidence": confidence(len(reqs)),
                "statuses": sorted(by_status),
                "query": sorted({q for r in reqs for q in r["query"]}),
                "auth": "bearer" if "bearer" in auths else "cookie" if "cookie" in auths else "none",
                "requestSchema": _schema([b for r in reqs for b in r["req_body"]], dropped),
                "responseSchemas": {str(code): _schema(bodies, dropped) for code, bodies in sorted(by_status.items()) if bodies},
            }
        )

    tls_hosts: dict[tuple, int] = {}
    for row in tls:
        if not host or row["sni"] == host or row["sni"].endswith("." + host):
            tls_hosts[(row["sni"], row["port"])] = tls_hosts.get((row["sni"], row["port"]), 0) + 1
    tls_out = [{"sni": sni, "port": port, "count": n} for (sni, port), n in sorted(tls_hosts.items(), key=lambda kv: -kv[1])]

    gaps = []
    for ep in endpoints:
        if ep["count"] == 1:
            gaps.append(f"{ep['method']} {ep['path']} was seen once (confidence {ep['confidence']}). Capture it again to confirm its shape.")
    statuses = [s for ep in endpoints for s in ep["statuses"]]
    if statuses and max(statuses) < 400:
        gaps.append("No 4xx/5xx response was observed. Error behaviour is not documented.")
    hosts = sorted({ep["host"] for ep in endpoints})
    if len(hosts) > 1:
        gaps.append(f"Calls to {len(hosts)} hosts are merged ({', '.join(hosts)}). Use --host to keep one API.")
    if source == "pcap" and endpoints:
        gaps.append("PCAP mode reads plaintext request lines only: no bodies, no status codes. A HAR of the same session gives schemas.")
    if tls_out:
        gaps.append(
            "Part of the traffic is TLS. Contour names the host (SNI) and does not decrypt it. "
            "A HAR exported from your own browser session contains those calls."
        )
    if not endpoints and not tls_out:
        gaps.append("No plaintext HTTP and no TLS SNI found. This file holds no readable application traffic.")
    if dropped:
        gaps.append(f"{len(dropped)} body key(s) looked like a secret and were dropped from the schemas.")
    if looks_live_secret(json.dumps({"endpoints": endpoints, "tls": tls_out})):
        gaps.append("A secret-looking string survived filtering. Do not publish this model.")

    return {
        "contour": "1",
        "meta": {
            "source": source,
            "tool": "contour-cli",
            "version": __version__,
            "legal": {
                "basis": "own-capture",
                "secretsRedacted": True,
                "drmCircumvention": False,
                "note": "Observed from a capture you are allowed to read. Not a decompiler, not source code.",
            },
        },
        "stats": {
            "records": records,
            "httpRequests": len(requests),
            "skippedStatic": skipped,
            "endpoints": len(endpoints),
            "tlsFlows": sum(row["count"] for row in tls_out),
            "secretsSeenInSource": secrets,
        },
        "endpoints": endpoints,
        "tls": tls_out,
        "gaps": gaps,
        "openapi": _openapi(endpoints),
    }


def _openapi(endpoints: list[dict]) -> dict:
    paths: dict[str, dict] = {}
    hosts: list[str] = []
    bearer = False
    for ep in endpoints:
        if ep["host"] and ep["host"] not in hosts:
            hosts.append(ep["host"])
        params = [
            {"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
            for name in re.findall(r"\{([^}]+)\}", ep["path"])
        ]
        params += [{"name": name, "in": "query", "schema": {"type": "string"}} for name in ep["query"]]
        op: dict = {}
        if params:
            op["parameters"] = params
        if ep["requestSchema"]:
            op["requestBody"] = {"content": {"application/json": {"schema": ep["requestSchema"]}}}
        responses: dict[str, dict] = {}
        for code in ep["statuses"]:
            responses[str(code)] = {"description": "Observed in the capture."}
            schema = ep["responseSchemas"].get(str(code))
            if schema:
                responses[str(code)]["content"] = {"application/json": {"schema": schema}}
        op["responses"] = responses or {"default": {"description": "Response not observed in the capture."}}
        if ep["auth"] == "bearer":
            op["security"] = [{"bearerAuth": []}]
            bearer = True
        op["x-contour-seen"] = ep["count"]
        op["x-contour-confidence"] = ep["confidence"]
        paths.setdefault(ep["path"], {})[ep["method"].lower()] = op
    spec: dict = {
        "openapi": "3.1.0",
        "info": {
            "title": hosts[0] if hosts else "capture",
            "version": "0.0.0-contour",
            "description": "Observed by Contour from an authorized capture. Not the source code.",
        },
        "servers": [{"url": f"https://{h}"} for h in hosts] or [{"url": "https://api.example.com"}],
        "paths": paths,
    }
    if bearer:
        spec["components"] = {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}}
    return spec
