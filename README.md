# agent-tool-gateway

A small, self-hosted Go gateway that exposes configured REST APIs as MCP tools. It gives agents one authenticated MCP endpoint while the gateway enforces a per-client tool allowlist and records metadata-only audit events.

> This is an educational MVP, not a complete enterprise control plane. It uses static JSON configuration and bearer tokens loaded from environment variables.

## What it does

- Serves MCP over Streamable HTTP using the official Go MCP SDK and its stateless transport mode.
- Maps a fixed set of REST endpoints to MCP tools; tool names and JSON input schemas come from trusted configuration.
- Authenticates MCP clients with bearer tokens and applies an explicit tool allowlist per client.
- Can attach a backend bearer token without placing the secret in the tool schema or logs.
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

- `clients`: client IDs, token environment-variable names, and allowed tool names. Each client must have an explicit non-empty allowlist.
- `tools`: tool name and description, fixed HTTP method and endpoint, optional backend-token environment-variable name, and an object JSON Schema.
- `request_timeout`, `max_request_bytes`, `max_response_bytes`, and `max_concurrent_tool_calls`: resource limits applied by the gateway.
- `metrics_token_env`: optional environment variable protecting `/metrics`. If empty, the endpoint returns 404.

For `GET` tools, input properties become query parameters. For other supported methods, the validated argument object is sent as a JSON body. Endpoint URLs are fixed in configuration; tool arguments cannot select a host or path.

Configuration is an administrator trust boundary. Keep it out of source control, keep credentials in environment variables or a secret manager, and enforce outbound network rules so the process can reach only intended backends. Use TLS termination and network isolation when exposing the gateway beyond localhost.

## Current scope

- Static configuration; no runtime registry or management API.
- REST-to-MCP tools only; no MCP-to-MCP federation.
- Bearer credentials are shared by configured client identity; no OAuth flow or delegated user identity.
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
