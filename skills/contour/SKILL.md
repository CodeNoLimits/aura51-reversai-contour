# Contour Skill — Signal Compiler

## Purpose
Contour is an agent skill that ingests signals from an application (network traffic and authorized local observations), normalizes them, and helps an LLM reconstruct an approximate functional model of the software.

## When to Use
- You have PCAP, HAR, or mitmproxy captures of software you lawfully use
- You want a clean-room description of observed behavior for interoperability
- You are contributing to the Aura 51 / ReversAi partner signal platform

## Inputs
- Capture files (PCAP, HAR, mitmproxy flows)
- Optional context: what the application does, known endpoints, user goals
- Contour Signal Format JSON (if already normalized)

## Outputs
- Structured summary of endpoints, message patterns, and sequences
- Approximate protocol model or state machine
- Clean-room notes or OpenAPI-like sketch
- Confidence scores and evidence pointers
- Identified gaps for further signal collection

## Workflow
1. Confirm legal basis and authorization
2. Ingest and normalize signals
3. Extract features (fields, lengths, sequences, response patterns)
4. Reason with the LLM to connect the dots
5. Produce a model with evidence
6. Iterate or export for sharing

## Mandatory Guardrails
- Only analyze software you own or are authorized to study
- Never circumvent technical protection measures
- Prefer passive observation
- Output must be original; do not copy protected expression
- Document provenance

## Integration
Works with Grok, Claude, Cursor, Codex, and other agents that support skills or MCP.  
Pairs well with binary tools such as REA for complementary analysis.

---
*Part of Aura 51 / ReversAi — Contour of Potential.*
