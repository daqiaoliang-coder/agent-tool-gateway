# agent-tool-gateway

A small, self-hosted Go gateway that exposes configured REST APIs as MCP tools. It gives agents one authenticated MCP endpoint while the gateway enforces a per-client tool allowlist and records metadata-only audit events.

> This is a self-hosted data-plane gateway, not a complete enterprise control plane. Tools and permissions use locally published JSON snapshots; credentials come from environment variables or a reloadable Secret file.

## What it does

- Serves single-message MCP requests over Streamable HTTP using the official Go MCP SDK and its stateless transport mode; JSON-RPC batches are rejected, including on legacy protocol versions.
- Maps a fixed set of REST endpoints to MCP tools; tool names and JSON input schemas come from trusted configuration.
- Authenticates every MCP request with a bearer token and applies the client's tool allowlist to both discovery and execution. Hidden tools are reported as unknown without exposing their descriptions or schemas.
- Can attach a backend bearer token without placing the secret in the tool schema or logs.
- Supports overlapping client/metrics tokens, activation/expiry times, and revocation through an atomically reloaded Secret file.
- Bounds request and response sizes, tool-call concurrency, and upstream duration; disables redirects.
- Audits authentication, protocol and policy rejections, schema validation, and upstream outcomes without recording arguments or response bodies; correlates requests with W3C trace context.
- Exposes protected Prometheus histograms, classified outcomes, saturation, and reload health, with example alert rules.
- Publishes versioned tool/permission snapshots atomically, supports deprecation and emergency disable, and preserves the previous generation on rejected releases.
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
- `tools`: tool name and description, `version` (default `1`), `state` (`active`, `deprecated`, or `disabled`; default `active`), fixed HTTP method and endpoint, optional backend-token environment-variable name, and an object JSON Schema. In file mode, `backend_token_required: true` requires a credential for that tool.
- `request_timeout`, `max_request_bytes`, `max_response_bytes`, and `max_concurrent_tool_calls`: resource limits applied by the gateway.
- `metrics_token_env`: optional environment variable protecting `/metrics` in environment mode. If empty, the endpoint returns 404.
- `credentials_file`: optional Secret file path, relative to the process working directory or absolute. File mode is exclusive: remove all `token_env`, `backend_token_env`, and `metrics_token_env` settings rather than mixing sources.

For `GET` tools, input properties become query parameters. For other supported methods, the validated argument object is sent as a JSON body. Endpoint URLs are fixed in configuration; tool arguments cannot select a host or path.

Configuration is an administrator trust boundary. Keep deployed files and secrets outside this repository; review secret-free templates in your controlled GitOps repository. Protect the configuration directory against untrusted writes, keep credentials in environment variables or a secret manager, and enforce outbound network rules so the process can reach only intended backends. Use TLS termination and network isolation when exposing the gateway beyond localhost.

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

## Tool and configuration releases

Each tool has a version label (1–128 letters, digits, `.`, `_`, or `-`) and a lifecycle state. `deprecated` remains callable and discoverable with `_meta["gateway/state"]`; `disabled` disappears from discovery and is rejected as an unknown tool. Discovery also exposes `_meta["gateway/version"]`. State and description changes need no version change. Changes to a tool's method, endpoint, input schema, or backend authentication contract require a different version from the active definition. Version labels are not ordered; a reviewed rollback may restore an older version.

Validate a candidate without opening a listener, reading credentials, or contacting an upstream:

```sh
go run ./cmd/gateway -check -config /etc/agent-tool-gateway/gateway.next.json
```

Preflight checks the full registry, including disabled/unassigned tools, using the SDK's schema and registration validation. It rejects duplicate JSON keys, unknown/case-variant configuration fields, invalid field types, explicit null configuration fields, invalid schemas/defaults, and unresolved references. JSON Schema's own vocabulary remains open. Files must be regular files of at most 1 MiB. The `configuration valid` event reports the canonical SHA-256 `config_revision`; whitespace and JSON object-key order do not change it. Credential references are hashed, not secret values. Preflight does **not** attest that credentials are available or that an upstream is healthy.

A local GitOps release flow is:

1. Review the secret-free change and version labels; retain the previous approved configuration outside this repository. Use the same gateway binary for preflight and production.
2. Write the candidate beside the deployed file and run `-check`. Ensure the current Secret file is valid for the candidate client/tool IDs, without reintroducing revoked tokens.
3. Atomically rename the candidate over the path passed to `-config`, then signal the gateway process:

   ```sh
   mv /etc/agent-tool-gateway/gateway.next.json /etc/agent-tool-gateway/gateway.json
   kill -USR1 <gateway-pid>
   ```

4. Require a `configuration reloaded` event and verify the expected revision using `X-Config-Revision` on `/readyz` or MCP responses and `agent_tool_gateway_config_info` on `/metrics`. A log contains both previous and activated revisions. Publishing the file alone changes nothing in memory.
5. To roll back, atomically restore the approved previous configuration to the same path, send SIGUSR1 again, and verify its revision. The current Secret must validate against that configuration; a configuration rollback never automatically restores historical secrets.

SIGUSR1 constructs and validates the entire candidate registry, allowlists, and current credentials before an atomic swap. An invalid configuration, invalid/unreadable Secret, or SDK registration failure leaves the previous generation active. SIGHUP remains **credential-only**, and is serialized with configuration publication. Full configuration publication reads the current process environment in environment mode; changing the invoking shell's environment cannot change an already-running process.

New requests use the new generation; admitted requests finish with their original registry, permissions, resource limits, and credential snapshot. Emergency disable therefore prevents **new** calls, not side effects already in flight. Generations share metric counters and the same concurrency pool, so a release cannot bypass occupied slots. Changes to `listen_addr`, `max_concurrent_tool_calls`, or `credentials_file` require a restart; other validated configuration fields can be published. During shutdown, readiness and new MCP requests return 503 while admitted requests drain.

This is per-process publication, not a cluster transaction or built-in approval/history service. Git/deployment tooling must own approval, artifact retention, rollout ordering, and the global immutability of tool versions; the gateway enforces version changes against its currently active definition. An operator who can rewrite configuration can change policy. Roll out and verify every replica, and alert on unexpected revision drift.

## Audit and observability

JSON stdout events include `http_request`, `mcp_operation`, `tool_call`, `upstream_request`, `config_reload`, and `credential_reload`. Request events carry a server-generated `request_id`, trace/span IDs, and the active `config_revision`; tool events also carry configured identity, tool/version/state, duration, and a classified outcome. No arguments, response bodies, bearer headers, arbitrary unknown tool/method/path strings, or raw upstream/decoder errors are logged. Unknown tools use `[unknown]`; unmatched routes/methods use `[other]`. Successful health probes and metrics scrapes are counted without repetitive audit logs.

HTTP observation surrounds routing, including 404/405, authentication failures, oversized bodies, and protocol rejection before SDK dispatch—even parameter decoding errors returned as HTTP 200. JSON-RPC batches are rejected before dispatch on every protocol version so a valid message cannot mask a rejected one in the same request. Typed tool calls are counted exactly once, including `tool_denied`, `tool_disabled`, `unknown_tool`, `invalid_arguments`, `overloaded`, `cancelled`, `timeout`, `backend_credential_unavailable`, `response_too_large`, `upstream_http_error`, and `upstream_error`. Malformed protocol envelopes are HTTP/protocol events, not executed tool calls. HTTP status alone is not a tool-success signal; use the tool outcome.

A valid W3C version-00 `traceparent` continues the caller's trace with fresh server/tool/upstream span IDs; missing, malformed, multiple, or unsupported-version headers start a new trace. The upstream receives a child `traceparent` and the gateway's `X-Request-ID`. Caller-provided request IDs, `baggage`, and `tracestate` are not propagated. Trace context is correlation data, never trusted identity. These are correlated structured span events, **not an OTLP exporter**; a collector/tracing backend and durable audit storage must be supplied externally. Stdout logging is not a tamper-proof audit ledger.

The protected `/metrics` endpoint exposes:

- `agent_tool_gateway_tool_calls_total{tool,outcome}` with classified outcomes (the old aggregate `outcome="error"` is replaced).
- `agent_tool_gateway_tool_call_duration_seconds` and `agent_tool_gateway_http_request_duration_seconds` histograms, including cumulative buckets, sum, and count.
- `agent_tool_gateway_http_requests_total{route,method,outcome,status}`, including authentication and protocol failures.
- `agent_tool_gateway_in_flight` and `agent_tool_gateway_concurrency_limit` for saturation.
- `agent_tool_gateway_reload_total{kind,outcome}`, `agent_tool_gateway_last_reload_success{kind}`, and `agent_tool_gateway_last_reload_success_timestamp_seconds{kind}`. Before any attempt, health/timestamp are zero; combine health with attempt count to avoid a startup false alarm.
- `agent_tool_gateway_config_info{revision}` for the current revision only.

Request, trace and client IDs are never metric labels. Tool names come only from trusted configuration; historical tool series are capped at 1,024 distinct names, then `[overflow]`, and unknown names share one series. Histograms cover all classified tool attempts, including rejections, so choose SLO queries accordingly.

[`configs/alerts.example.yml`](configs/alerts.example.yml) includes availability, persistent reload rejection, saturation, execution failure ratio, latency, authentication failure, and replica-drift alerts. Add it to your Prometheus `rule_files`, configure authenticated scraping and Alertmanager routing, and adjust the example thresholds to your SLO. The availability rule assumes job `agent-tool-gateway`; the drift rule assumes replicas within a job should have identical rendered configurations. Validate rules with `promtool check rules configs/alerts.example.yml` before deployment. A disabled/expired metrics credential also makes scraping fail; distinguish that from process failure.

For an incident: find `request_id` in HTTP audit, follow `trace_id` through the tool and upstream events, check `outcome`/status/duration, then identify the deployed `config_revision` and tool version. Investigate reload rejections immediately because old permissions/credentials can remain active. Do not enable body/header capture to diagnose a denial. No automatic tool retries are introduced.

## Current scope

- File/GitOps-based publication; no management API, approval UI, persistent registry database, or cluster-wide transaction.
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
