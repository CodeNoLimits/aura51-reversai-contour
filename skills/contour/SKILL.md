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
2. Run `python -m contour.cli analyze capture.pcap -o model.json`
3. Read endpoints and gaps. If the gap says TLS, ask for a HAR of their own session. Do not break the TLS.
4. Run `python -m contour.cli sdk model.json -o sdk_out` only if the spec is theirs
5. The client takes `base_url` and `token` at runtime, supplied by the customer

## Guardrails
- Secrets are stripped before the model is written. If one remains, stop.
- Confidence stays attached to evidence. Gaps stay written.
- Original expression only. No copied source.
