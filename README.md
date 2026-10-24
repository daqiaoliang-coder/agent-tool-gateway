# agent-tool-gateway

A small, self-hosted Go gateway that exposes configured REST APIs as MCP tools. It gives agents one authenticated MCP endpoint while the gateway enforces a per-client tool allowlist and records metadata-only audit events.

> This is an educational MVP, not a complete enterprise control plane. It uses static tool/permission configuration and bearer tokens loaded from environment variables or a reloadable Secret file.

## What it does

- Serves MCP over Streamable HTTP using the official Go MCP SDK and its stateless transport mode.
- Maps a fixed set of REST endpoints to MCP tools; tool names and JSON input schemas come from trusted configuration.
- Authenticates every MCP request with a bearer token and applies the client's tool allowlist to both discovery and execution. Hidden tools are reported as unknown without exposing their descriptions or schemas.
- Can attach a backend bearer token without placing the secret in the tool schema or logs.
- Supports overlapping client/metrics tokens, activation/expiry times, and revocation through an atomically reloaded Secret file.
- Bounds request and response sizes, tool-call concurrency, and upstream duration; disables redirects.
- Emits structured audit records without arguments or response bodies, plus an optional protected Prometheus endpoint.
- Includes a local demo backend so the flow can be tried without external services.

The gateway does not run an agent, call an LLM, or proxy another MCP server. It is the tool-access edge between an MCP client and configured REST APIs.

## Quick start

Requires Go 1.25 or newer.

```sh
cp configs/gateway.example.json configs/gateway.json
export ATG_DEMO_CLIENT_TOKEN="$(openssl rand -hex 32)"
export ATG_METRICS_TOKEN="$(openssl rand -hex 32)"
```

Start the demo backend in one terminal:

```sh
go run ./cmd/demo-backend
```

Start the gateway in another terminal:

```sh
go run ./cmd/gateway -config configs/gateway.json
```

The MCP endpoint is `http://127.0.0.1:8080/mcp`. Configure an MCP client to use that Streamable HTTP URL and send `Authorization: Bearer $ATG_DEMO_CLIENT_TOKEN`. The configured client can call `service_health` and `echo_message`.

Health and metrics endpoints:

```sh
curl -i http://127.0.0.1:8080/healthz
curl -H "Authorization: Bearer $ATG_METRICS_TOKEN" http://127.0.0.1:8080/metrics
```

Build both binaries:

```sh
go build ./cmd/gateway ./cmd/demo-backend
```

## Configuration

Start from [`configs/gateway.example.json`](configs/gateway.example.json). Important fields:

- `clients`: client IDs, token environment-variable names, and allowed tool names. Each client must have an explicit non-empty allowlist. Gateway authentication tokens must be distinct across clients and metrics, and must not be reused as backend tokens.
- `tools`: tool name and description, fixed HTTP method and endpoint, optional backend-token environment-variable name, and an object JSON Schema. In file mode, `backend_token_required: true` requires a credential for that tool.
- `request_timeout`, `max_request_bytes`, `max_response_bytes`, and `max_concurrent_tool_calls`: resource limits applied by the gateway.
- `metrics_token_env`: optional environment variable protecting `/metrics` in environment mode. If empty, the endpoint returns 404.
- `credentials_file`: optional Secret file path, relative to the process working directory or absolute. File mode is exclusive: remove all `token_env`, `backend_token_env`, and `metrics_token_env` settings rather than mixing sources.

For `GET` tools, input properties become query parameters. For other supported methods, the validated argument object is sent as a JSON body. Endpoint URLs are fixed in configuration; tool arguments cannot select a host or path.

Configuration is an administrator trust boundary. Keep it out of source control, keep credentials in environment variables or a secret manager, and enforce outbound network rules so the process can reach only intended backends. Use TLS termination and network isolation when exposing the gateway beyond localhost.

## Credential lifecycle

Environment mode remains available for local use. Tokens are read once at startup; changing a shell environment does not update a running process, and SIGHUP does not reload environment credentials.

For online credential management, set `credentials_file` to a protected path outside the repository, for example `/run/secrets/agent-tool-gateway.json`, and remove the environment-variable credential settings. Keep client IDs and allowlists in the gateway configuration. Set `backend_token_required: true` on every tool that needs backend authentication; leaving it false declares that backend anonymous, and supplying a credential for such a tool is rejected.

The Secret file is a JSON object with this shape. Replace every placeholder before use; generate distinct random client and metrics tokens with `openssl rand -hex 32`, and obtain backend credentials from the upstream service:

```json
{
  "clients": {
    "demo-client": [
      {
        "token": "REPLACE_WITH_CLIENT_TOKEN",
        "expires_at": "REPLACE_WITH_RFC3339_EXPIRY"
      }
    ]
  },
  "backends": {
    "echo_message": {
      "token": "REPLACE_WITH_BACKEND_TOKEN",
      "expires_at": "REPLACE_WITH_RFC3339_EXPIRY"
    }
  },
  "metrics": [
    {
      "token": "REPLACE_WITH_METRICS_TOKEN",
      "expires_at": "REPLACE_WITH_RFC3339_EXPIRY"
    }
  ]
}
```

This example requires `backend_token_required: true` on `echo_message`; omit its backend entry when using the unauthenticated demo backend. Client keys must match configured client IDs, and backend keys must match configured authenticated tool names.

- Each credential accepts optional `not_before`, `expires_at` (RFC3339), and `revoked` fields. It is usable when not revoked and `not_before <= now < expires_at`. An omitted time leaves that bound open; use explicit expiries in production.
- Client and metrics tokens must contain at least 32 characters. Tokens must use HTTP Bearer syntax. Fixed field names are case-sensitive, and credential fields cannot explicitly be `null`. Unknown fields, duplicate JSON keys, invalid time ranges, and conflicting tokens reject the entire update without logging the Secret contents.
- The file must be a regular file with no group/other permissions (use `0400` or `0600`) and at most 1 MiB. Projected Secret symlinks are supported when the target satisfies these checks. Protect the containing directory and never commit the file. This is filesystem access control, not encryption or a built-in Secret manager.

To rotate, first add the new client token alongside the old one in the same client's array. Write an owner-only replacement file in the same directory, atomically rename it over the configured file, then send SIGHUP to each gateway process (not the `go run` parent):

```sh
kill -HUP <gateway-pid>
```

After clients switch, remove the old token or mark it `revoked: true`, replace the file, and send SIGHUP again. Metrics tokens use the same overlap flow. Each backend has a single active credential; coordinate its replacement with the upstream service's rotation window.

A successful reload atomically switches client, backend, and metrics credentials for new requests without changing tool permissions, concurrency limits, or metric counters. Already admitted requests retain their original credential snapshot and are not cancelled; backend validity is checked again before forwarding. Expiry takes effect by time without another reload.

Missing client entries or empty token arrays deny that client's new requests. Missing, revoked, not-yet-active, or expired required backend credentials reject the tool call before any network request, never falling back to anonymous access. Empty/missing metrics credentials disable `/metrics`. An empty document `{}` revokes all new client access and disables metrics.

Invalid, unreadable, or insecure files leave the previous snapshot active, with its original expiry times still enforced. Watch the `credentials reloaded` and `credential reload rejected; previous credentials remain active` log events; a rejected reload is not a successful revocation. No fallback to environment credentials occurs in file mode. Updates are per process, not cluster-wide transactions.

## Current scope

- Tool registrations, client identities, and allowlists remain static; changes require restarting every instance. Credential rotation and revocation in file mode do not require a restart. There is no runtime registry or management API.
- REST-to-MCP tools only; no MCP-to-MCP federation.
- Bearer credentials identify configured clients; no OAuth flow, delegated user identity, or tenant/resource-level authorization.
- Synchronous tool calls; no durable queue or background task store.
- Audit logs intentionally omit request arguments and tool response bodies.

## Design sketch

```text
MCP client
   │ Streamable HTTP + bearer token
   ▼
agent-tool-gateway
   ├── client authentication and tool allowlist
   ├── MCP schema validation and resource limits
   ├── metadata-only audit and metrics
   ▼
configured REST endpoints
```

## License

MIT. See [LICENSE](LICENSE).
