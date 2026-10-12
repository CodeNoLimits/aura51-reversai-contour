# Contour — Signal-Based Reverse Engineering

**by Aura 51 / ReversAi**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![GitHub stars](https://img.shields.io/github/stars/CodeNoLimits/aura51-reversai-contour)](https://github.com/CodeNoLimits/aura51-reversai-contour/stargazers)

> Capture the signals an application already received, on a session you are allowed to observe. Compile them into endpoints, gaps, and a client. Do not reconstruct the program.

Contour is an open-source platform and agent skill for **legal reverse engineering via signals**.  
It normalizes network traffic and local observations, then uses an LLM to approximate protocols, state machines, and functional models without needing (or touching) the binary.

Designed for interoperability research, clean-room reimplementation, security analysis of software you own, and collaborative signal sharing on GitHub.

## Why Contour?

Most reverse engineering focuses on binaries (Ghidra, IDA, REA, etc.).  
Many valuable systems today are **SaaS, Electron apps, or subscription software** where the interesting part is the protocol and runtime behavior.

Contour specializes in the **signal layer**:
- Network flows (PCAP, HAR)
- What was in clear, and what stayed encrypted
- A typed client generated from the observed OpenAPI

It does not decrypt TLS, it does not read a consumer subscription as an API, and it does not dump payloads.

## Two layers

This repository is the public layer. It is free, runnable, and the thing people can star and show. That is the advertisement.

A paid mission — an OpenAPI spec and a typed SDK in 48 hours, on a session the customer authorizes in writing — is a service. It is not shipped here. A closed tool does not travel, and a chat subscription is not an API.

It is complementary to binary tools like [REA](https://github.com/morluto/rea).

## Quick Start

```bash
git clone https://github.com/CodeNoLimits/aura51-reversai-contour
cd aura51-reversai-contour

python -m venv .venv
source .venv/bin/activate   # ou .venv\Scripts\activate sous Windows
pip install -r requirements.txt

python -m contour.cli analyze examples/sample.pcap -o model.json
python -m contour.cli sdk model.json -o sdk_out
```

`analyze` lit un PCAP, un PCAPNG, ou un HAR. Le HTTP en clair devient des endpoints et un OpenAPI 3.1. Le TLS est nommé par le SNI, et les corps restent fermés. Les jetons, cookies et e-mails ne sortent pas dans `model.json`.

`sdk` écrit `client.py` et `client.ts`, sans dépendance, depuis cet OpenAPI. L'URL et le jeton se passent au client au moment de l'appel, sur une API que le client t'a autorisée. Ce n'est pas un passe pour un abonnement grand public.

Le modèle est l'entrée d'un agent. Le CLI ne prétend pas reconstruire le programme.

## Architecture

```
Signals (PCAP / HAR / mitm / local traces)
        ↓
Contour Normalizer → Contour Signal Format (JSON)
        ↓
LLM Reasoning Layer (pluggable: local or cloud)
        ↓
Model (protocol description, state machine, clean-room notes, OpenAPI sketch)
        ↓
Optional: share anonymized packs on GitHub
```

## Legal Guardrails

Contour is built for **lawful use only**:
- Software you own or are authorized to analyze
- Interoperability (DMCA §1201(f), EU Software Directive Art. 6)
- Clean-room methods
- Security research with proper authorization
- No circumvention of technical protection measures
- No copying of protected expression

See [LEGAL.md](LEGAL.md) for details.

## Project Structure

- `contour/` — Core analyzer and CLI
- `skills/contour/` — Agent skill definition
- `docs/` — Format specs and architecture
- `examples/` — Sample traces and expected outputs
- `CONTRIBUTING.md` — How to add signal packs and models

## Roadmap

- [x] Contour model v0.2 (endpoints, gaps, OpenAPI, redaction)
- [x] PCAP / PCAPNG / HAR analyzer that refuses to emit secrets
- [x] SDK generator (`client.py`, `client.ts`)
- [ ] Partner packs, after a written authorization
- [ ] Enterprise features (audit trails, on-prem)

## Contributing

We welcome signal packs, protocol models, importers, and documentation.  
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

---

**Aura 51** — Contour of Potential.  
Built for the signal layer of reverse engineering.
