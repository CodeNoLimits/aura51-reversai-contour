# Contour Signal Format v0.1

Normalized representation of application signals for AI reasoning and sharing.

```json
{
  "meta": {
    "source": "pcap|har|mitm|frida|mixed",
    "captured_at": "2026-10-12T00:00:00Z",
    "app_context": "optional description of the target application",
    "legal_basis": "owned|authorized|public_protocol|research",
    "tool": "contour"
  },
  "flows": [
    {
      "id": "flow-1",
      "protocol": "HTTPS|MQTT|custom",
      "endpoint": "api.example.com/v1/chat",
      "direction": "client->server",
      "samples": [
        {
          "request_summary": "POST with JSON body",
          "response_summary": "200 with streaming chunks",
          "inferred_fields": [
            {"name": "model", "type": "string", "confidence": 0.9}
          ]
        }
      ]
    }
  ],
  "sequences": [
    {"name": "auth_flow", "steps": ["login", "token_refresh", "api_call"], "confidence": 0.7}
  ],
  "gaps": ["need unencrypted payloads", "missing error cases"],
  "model_notes": "optional LLM-generated observations"
}
```

This format is the common language for Contour contributions.
