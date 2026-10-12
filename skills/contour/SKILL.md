# Contour Skill — Signal Compiler

## Purpose
Compile signals an application already received, on a session the operator is allowed to observe. Produce endpoints, gaps, and a typed client. Do not reconstruct the program, and do not present the result as a replacement subscription.

## When to Use
- A PCAP, PCAPNG, or HAR from a session the operator owns or was authorized in writing to observe
- An OpenAPI they already hold, to generate `client.py` and `client.ts`

## Do not use
- A consumer subscription (ChatGPT Plus or Max, Claude Max or Pro, or the same pattern) as if it were an API
- Tokens scraped from a web app
- TLS decryption of traffic the operator did not key themselves
- Raw payload dumps, cookies, or live secrets

## Workflow
1. Confirm the written authorization before any capture
2. Run `python3 -m contour analyze capture.har --host api.their-app.com -o model.json --openapi openapi.json` (PCAP/PCAPNG also accepted)
3. Read endpoints, confidence and gaps. Operations under 0.75 were seen once: ask for another capture of that flow. If a gap says TLS, ask for a HAR of their own session. Do not break the TLS.
4. Run `python3 -m contour sdk openapi.json -o sdk_out` only if the spec is theirs
5. The client takes `base_url` and `token` at runtime, supplied by the customer

## Guardrails
- Values never enter the model, only structure. If the CLI refuses with exit code 2, a secret survived: stop.
- Confidence stays attached to evidence. Gaps stay written.
- Original expression only. No copied source.
