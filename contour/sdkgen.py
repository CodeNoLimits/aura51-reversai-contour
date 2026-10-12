#!/usr/bin/env python3
"""
DREAMNOVA SDKGEN — génère un client SDK typé (Python + TypeScript) à partir
d'une spec OpenAPI que TU DÉTIENS LÉGITIMEMENT (ta propre API, celle d'un
client qui t'a mandaté, ou une API publique à conditions permissives).

C'est le livrable que tu factures dans l'offre « j'intègre ton API en 48h ».
Entrée  : openapi.json  (ou .yaml si PyYAML est installé)
Sorties : client.py  + client.ts  (clients prêts à l'emploi, zéro magie)

Aucune dépendance obligatoire (stdlib pure). PyYAML seulement si tu passes un .yaml.
Tam-coding : un fichier, lisible, prêt au copier-coller chez le client.
"""

from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path

# --- Variables critiques -----------------------------------------------------
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def load_spec(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # optionnel
        except ImportError:
            sys.exit("[sdkgen] .yaml fourni mais PyYAML absent. "
                     "Fais `pip install pyyaml` ou convertis en .json.")
        return yaml.safe_load(text)
    return json.loads(text)


def op_name(method: str, path: str, op: dict) -> str:
    """operationId si présent, sinon un nom lisible depuis method + path."""
    if op.get("operationId"):
        raw = op["operationId"]
    else:
        parts = [p for p in path.split("/") if p and not p.startswith("{")]
        raw = method + "_" + "_".join(parts or ["root"])
    # snake_case propre
    s = re.sub(r"[^0-9a-zA-Z]+", "_", raw).strip("_").lower()
    return s or f"{method}_op"


def path_params(path: str) -> list[str]:
    return re.findall(r"\{([^}]+)\}", path)


def query_params(op: dict) -> list[str]:
    return [p["name"] for p in op.get("parameters", [])
            if p.get("in") == "query"]


def has_body(op: dict) -> bool:
    return bool(op.get("requestBody"))


def iter_ops(spec: dict):
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() in HTTP_METHODS and isinstance(op, dict):
                yield method.lower(), path, op


def base_url(spec: dict) -> str:
    servers = spec.get("servers") or []
    if servers and servers[0].get("url"):
        return servers[0]["url"].rstrip("/")
    return "https://api.example.com"


# --- Générateur PYTHON (urllib, zéro dépendance) -----------------------------
def gen_python(spec: dict) -> str:
    title = (spec.get("info", {}).get("title") or "API").strip()
    L = [
        '"""Client ' + title + ' — généré par DreamNova sdkgen. Zéro dépendance."""',
        "import json, urllib.request, urllib.parse",
        "",
        "",
        "class ApiError(Exception):",
        "    def __init__(self, status, body):",
        "        super().__init__(f'HTTP {status}: {body[:200]}')",
        "        self.status, self.body = status, body",
        "",
        "",
        "class Client:",
        f"    def __init__(self, base_url={base_url(spec)!r}, token=None, headers=None):",
        "        self.base_url = base_url.rstrip('/')",
        "        self.token = token",
        "        self.headers = headers or {}",
        "",
        "    def _request(self, method, path, query=None, body=None):",
        "        url = self.base_url + path",
        "        if query:",
        "            q = {k: v for k, v in query.items() if v is not None}",
        "            if q:",
        "                url += '?' + urllib.parse.urlencode(q)",
        "        data = json.dumps(body).encode() if body is not None else None",
        "        h = {'Accept': 'application/json', **self.headers}",
        "        if body is not None:",
        "            h['Content-Type'] = 'application/json'",
        "        if self.token:",
        "            h['Authorization'] = f'Bearer {self.token}'",
        "        req = urllib.request.Request(url, data=data, headers=h, method=method)",
        "        try:",
        "            with urllib.request.urlopen(req, timeout=60) as r:",
        "                raw = r.read().decode()",
        "                return json.loads(raw) if raw else None",
        "        except urllib.error.HTTPError as e:",
        "            raise ApiError(e.code, e.read().decode())",
        "",
    ]
    for method, path, op in iter_ops(spec):
        name = op_name(method, path, op)
        pp = path_params(path)
        qp = query_params(op)
        body = has_body(op)
        args = ["self"] + pp + [f"{q}=None" for q in qp]
        if body:
            args.append("body=None")
        pypath = re.sub(r"\{([^}]+)\}", lambda m: "{" + m.group(1) + "}", path)
        qdict = "{" + ", ".join(f"{q!r}: {q}" for q in qp) + "}" if qp else "None"
        summary = (op.get("summary") or op.get("description") or "").strip().split("\n")[0]
        L.append(f"    def {name}({', '.join(args)}):")
        if summary:
            L.append(f'        """{summary}"""')
        L.append(f"        return self._request({method.upper()!r}, f{pypath!r}, "
                 f"query={qdict}, body={'body' if body else 'None'})")
        L.append("")
    return "\n".join(L) + "\n"


# --- Générateur TYPESCRIPT (fetch) -------------------------------------------
def gen_typescript(spec: dict) -> str:
    title = (spec.get("info", {}).get("title") or "API").strip()
    L = [
        f"// Client {title} — généré par DreamNova sdkgen. Fetch natif, zéro dépendance.",
        "export interface ClientOptions { baseUrl?: string; token?: string; headers?: Record<string,string>; }",
        "",
        "export class ApiError extends Error {",
        "  constructor(public status: number, public body: string) {",
        "    super(`HTTP ${status}: ${body.slice(0,200)}`);",
        "  }",
        "}",
        "",
        "export class Client {",
        "  baseUrl: string; token?: string; headers: Record<string,string>;",
        f"  constructor(o: ClientOptions = {{}}) {{",
        f"    this.baseUrl = (o.baseUrl ?? {base_url(spec)!r}).replace(/\\/$/, '');",
        "    this.token = o.token;",
        "    this.headers = o.headers ?? {};",
        "  }",
        "",
        "  private async _request(method: string, path: string, query?: Record<string,any>, body?: any) {",
        "    let url = this.baseUrl + path;",
        "    if (query) {",
        "      const q = new URLSearchParams();",
        "      for (const [k,v] of Object.entries(query)) if (v !== undefined && v !== null) q.append(k, String(v));",
        "      const s = q.toString(); if (s) url += '?' + s;",
        "    }",
        "    const h: Record<string,string> = { 'Accept': 'application/json', ...this.headers };",
        "    if (body !== undefined) h['Content-Type'] = 'application/json';",
        "    if (this.token) h['Authorization'] = `Bearer ${this.token}`;",
        "    const res = await fetch(url, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined });",
        "    const txt = await res.text();",
        "    if (!res.ok) throw new ApiError(res.status, txt);",
        "    return txt ? JSON.parse(txt) : null;",
        "  }",
        "",
    ]
    for method, path, op in iter_ops(spec):
        name = _camel(op_name(method, path, op))
        pp = path_params(path)
        qp = query_params(op)
        body = has_body(op)
        params = [f"{p}: string" for p in pp]
        params += [f"{q}?: any" for q in qp]
        if body:
            params.append("body?: any")
        tspath = "`" + re.sub(r"\{([^}]+)\}", lambda m: "${" + m.group(1) + "}", path) + "`"
        qobj = "{" + ", ".join(f"{q}" for q in qp) + "}" if qp else "undefined"
        summary = (op.get("summary") or op.get("description") or "").strip().split("\n")[0]
        if summary:
            L.append(f"  /** {summary} */")
        L.append(f"  {name}({', '.join(params)}) {{")
        L.append(f"    return this._request({method.upper()!r}, {tspath}, {qobj}, "
                 f"{'body' if body else 'undefined'});")
        L.append("  }")
        L.append("")
    L.append("}")
    return "\n".join(L) + "\n"


def _camel(s: str) -> str:
    parts = s.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def generate(spec: dict) -> tuple[str, str, int]:
    ops = list(iter_ops(spec))
    return gen_python(spec), gen_typescript(spec), len(ops)


def main():
    ap = argparse.ArgumentParser(description="DreamNova sdkgen — OpenAPI -> client TS + Python")
    ap.add_argument("spec", help="openapi.json (ou .yaml avec PyYAML)")
    ap.add_argument("--out", default="./sdk_out", help="Dossier de sortie")
    args = ap.parse_args()

    p = Path(args.spec)
    if not p.exists():
        sys.exit(f"[sdkgen] Spec introuvable : {p}")
    spec = load_spec(p)
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)

    ops = list(iter_ops(spec))
    (out / "client.py").write_text(gen_python(spec))
    (out / "client.ts").write_text(gen_typescript(spec))
    print(f"[sdkgen] {len(ops)} opérations générées.")
    print(f"[sdkgen] -> {out/'client.py'}")
    print(f"[sdkgen] -> {out/'client.ts'}")


if __name__ == "__main__":
    main()
