# Contour

**Turn a HAR/PCAP you're allowed to capture into an OpenAPI spec + typed TS/Python SDK.**

[![CI](https://github.com/CodeNoLimits/aura51-reversai-contour/actions/workflows/ci.yml/badge.svg)](https://github.com/CodeNoLimits/aura51-reversai-contour/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Dependencies: none](https://img.shields.io/badge/dependencies-none%20(stdlib)-brightgreen.svg)](pyproject.toml)

You export a session of an app you are authorized to observe: your own, or a client's who signed off in writing. Contour compiles it into an OpenAPI 3.1 spec, a confidence score for every operation, a written list of what it could not see, and a one-file client for TypeScript and Python.

Values never make it into the output, only structure (keys, types, status codes). Contour doesn't decompile anything and never needs your source code.

*by Aura 51 / ReversAi*

## Quickstart

Python 3.10+, standard library only. No install step.

```bash
git clone https://github.com/CodeNoLimits/aura51-reversai-contour && cd aura51-reversai-contour
python3 -m contour analyze examples/sample.har --openapi openapi.json
python3 -m contour sdk openapi.json -o sdk_out
```

Then run it on your own traffic. [Export a HAR from your browser](docs/export-a-har.md), then:

```bash
python3 -m contour analyze session.har --host api.yourapp.com --openapi openapi.json
```

Want a `contour` command? Run `pip install .` inside a virtualenv, or `pipx install .`. PCAP/PCAPNG input needs scapy: `pip install '.[pcap]'`.

## Before / after

The input is [`examples/sample.har`](examples/sample.har): 13 entries from a fictional orders API. It contains a bearer token, a session cookie, a customer's email, a JS bundle and a `data:` URL, all fake.

```console
$ python3 -m contour analyze examples/sample.har --openapi openapi.json
Model written to model.json
OpenAPI written to openapi.json
5 operations from 12 requests (1 static skipped), 0 TLS flows, 12 secret-looking strings in the source (none copied)
  GET    /v1/customers/{id}                       seen   1x  confidence 0.50
  GET    /v1/orders                               seen   2x  confidence 0.75
  POST   /v1/orders                               seen   4x  confidence 0.94
  GET    /v1/orders/{id}                          seen   3x  confidence 0.88
  PATCH  /v1/orders/{id}                          seen   1x  confidence 0.50
Gap: GET /v1/customers/{id} was seen once (confidence 0.5). Capture it again to confirm its shape.
Gap: PATCH /v1/orders/{id} was seen once (confidence 0.5). Capture it again to confirm its shape.

$ python3 -m contour sdk openapi.json -o sdk_out
5 operations
sdk_out/client.py
sdk_out/client.ts
```

An excerpt from the generated `client.ts`:

```ts
export type PostV1OrdersRequest = { customer_id: string; items: Array<{ sku: string; qty: number }>; coupon?: string | null };

  /** POST /v1/orders — seen 4x, confidence 0.94 */
  postV1Orders(body?: PostV1OrdersRequest): Promise<PostV1OrdersResponse> {
    return this._request("POST", `/v1/orders`, undefined, body);
  }
```

The full output is committed, so you can read it without running anything: [`openapi.json`](examples/output/openapi.json) · [`client.ts`](examples/output/client.ts) · [`client.py`](examples/output/client.py) · [`model.json`](examples/output/model.json). A test regenerates these files on every CI run and fails if they drift.

## What you get

| | |
|---|---|
| **OpenAPI 3.1** | Paths with templated ids (`{id}`, `{id2}`), path and query parameters, JSON request/response schemas per status code (required keys, nullable fields) and a bearer security scheme. CI validates the spec with `openapi-spec-validator`. |
| **Confidence per operation** | `1 − 0.5^seen`: seen once = 0.50, twice = 0.75, four times = 0.94, capped at 0.99. It counts evidence and does not guarantee correctness. It's also exported as `x-contour-seen` / `x-contour-confidence` and copied into each SDK method's doc comment. |
| **Gaps, written down** | Operations seen only once, no 4xx/5xx observed, several hosts merged, TLS that was not decrypted, PCAP without bodies. You know what to capture next. |
| **Secrets stay out** | Header and body values are never copied. Tokens and emails in URL paths are masked, and keys that look like secrets are dropped. If anything secret-looking survives anyway, the export is **refused** (exit code 2, nothing written). `contour sdk` runs the same check on any spec you feed it. |
| **Typed SDKs, zero dependencies** | `client.ts` uses native `fetch` and exports request/response types. `client.py` uses `urllib` and `TypedDict`. One file each. CI type-checks both with `tsc --strict` and `mypy --strict`, and tests both against a local HTTP server. Path parameters are URL-encoded. |
| **PCAP aware** | Reads plaintext HTTP/1.x request lines and names TLS flows by SNI. It never decrypts them, and it says so in the gaps. |

`model.json` is meant to be handed to an agent: see [`skills/contour/SKILL.md`](skills/contour/SKILL.md). The CLI makes no network calls and uses no LLM.

## Try it in your browser — nothing leaves your machine

Don't want to clone anything? There's a browser version at **[dreamnova.studio/aura51/contour/har-to-openapi](https://dreamnova.studio/aura51/contour/har-to-openapi/)**. Drop a HAR on it and you get the spec and both clients. The file is parsed in your tab and is never uploaded.

## Why not mitmproxy2swagger / Optic / har-to-openapi?

They're good tools, and depending on your job one of them may suit you better:

- **[har-to-openapi](https://github.com/jonluca/har-to-openapi)** is the most complete HAR → spec converter: it merges several HARs, extracts reusable components, keeps examples, supports overlays and validation, and has opt-in redaction. If all you need is a rich spec, start there.
- **[mitmproxy2swagger](https://github.com/alufers/mitmproxy2swagger)** is the natural choice if you already capture with mitmproxy. Its two-pass workflow lets you pick path templates by hand.
- **[Optic](https://github.com/opticdev/optic)** keeps an *existing* spec accurate: diffs, breaking-change checks, lint rules in CI.

Contour makes a different bet:

1. **Safe by default, not opt-in.** There's no examples mode at all, and a secret-looking string blocks the export instead of producing a warning.
2. **Honest about uncertainty.** Every operation carries a confidence score, and what was not observed is written down as a gap rather than guessed.
3. **Spec and SDK in one step.** You get one-file TS + Python clients without openapi-generator or a Java toolchain, and both pass strict type checks.
4. **Nothing to install.** It runs from a clone with `python3`, standard library only. PCAP support (scapy) is optional.

### Known limits

- Schemas only contain what was observed. A field that never appeared is missing, and a field only ever seen as `null` stays `null`.
- Path templating is a heuristic: numbers, UUID/hex runs and prefixed ids (`cus_123`) become parameters. Slugs such as `/products/blue-shirt` stay literal.
- Only JSON bodies are modelled. Form data, multipart and GraphQL operation names are not (every GraphQL call is `POST /graphql`).
- In PCAP mode, Contour reads plaintext HTTP/1.x requests only: no TCP reassembly, no HTTP/2, no responses.

## Need it production-grade in 48h?

Contour is the open-source core of a paid service by Aura 51. You authorize a session in writing, we compile it, and in 48 hours you get a reviewed OpenAPI spec (operation names, summaries, shared components, error models), the typed SDKs, and a confidence report that lists what is still uncaptured. We never get access to your source code, and secrets stay masked.

| Mission | Price |
|---|---|
| Spec only | $1,750 |
| Spec + typed SDKs | $2,900 |
| Integration with your team | from $3,500 |

**[See the offer](https://dreamnova.studio/aura51/contour/en/)** · **[Book a 20-min discovery call](https://calendly.com/airbnbboosterchannel/aura-51-discovery-call)**

## Legal and ethics

Use Contour only on traffic you're allowed to capture: your own apps, or a client's with written authorization. It is not a decompiler and it doesn't reconstruct third-party software. It is not a tool for bypassing authentication, DRM or TLS, and it does not turn a consumer subscription into an API. Read [LEGAL.md](LEGAL.md) before use. It is a framework, not legal advice.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt        # editable install + scapy + pytest
python -m pytest -q
```

Layout: `contour/` (analyzer, redaction, SDK generator, CLI) · `tests/` · `examples/` (fictional captures + committed output) · `docs/` · `skills/contour/` (agent skill).

Contributions are welcome, especially signal packs, importers and fixes: see [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md). Release notes are in the [CHANGELOG](CHANGELOG.md).

## En français

Contour transforme une session réseau que tu as le droit de capturer (HAR ou PCAP) en spec OpenAPI 3.1, avec un score de confiance par opération, une liste écrite des trous et un SDK TypeScript + Python sans dépendance. Les valeurs ne sortent jamais : seulement la structure. Ce n'est pas un décompilateur. Besoin d'une version revue et livrée en 48 h, sous mandat écrit et sans accès à ton code ? Spec seule 1 500 € · Spec + SDK 2 500 € · Intégration dès 3 000 €. Voir [l'offre](https://dreamnova.studio/aura51/contour/) ou [réserver un appel](https://calendly.com/airbnbboosterchannel/aura-51-discovery-call).

## License

MIT, see [LICENSE](LICENSE). The Aura 51 and ReversAi names are not licensed for use as trademarks.
