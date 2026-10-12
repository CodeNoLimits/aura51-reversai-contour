# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | yes |
| < 0.2 | no |

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
<https://github.com/CodeNoLimits/aura51-reversai-contour/security/advisories/new>

Include the Contour version, the command you ran, and a **synthetic** input that reproduces the problem. Never send a real capture, token or customer data. We aim to acknowledge reports within a few business days.

## What we treat as a vulnerability

- **Secret leakage.** A token, cookie, key, email or body value ends up in `model.json`, `openapi.json`, `client.py` or `client.ts` even though the filter should have stopped it.
- **Code injection through generated clients.** Crafted HAR or OpenAPI content that makes `client.py` or `client.ts` execute something other than the intended HTTP call.
- **Unsafe parsing.** A crafted capture that makes `contour analyze` read or write files outside the paths you gave it, or execute code.

## Out of scope

- Captures you were not authorized to make. See [LEGAL.md](LEGAL.md).
- Large inputs that are merely slow.
- Secrets inside the HAR or PCAP file itself. Protect that file as described in [docs/export-a-har.md](docs/export-a-har.md).
