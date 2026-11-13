# Lifecycle and readiness

The authz server doesn't evaluate authorization requests until it loads its policies. This page describes the server lifecycle, the flags that control it, and how the server behaves when policies are missing or invalid.

## Phases

```
Starting ──► Syncing ──► Ready ──► Draining
                           │  ▲
                           ▼  │
                         Degraded
```

| Phase | Behavior |
|---|---|
| Starting | The process is up. Liveness passes, and readiness fails. |
| Syncing | The server loads every configured policy source: Kubernetes informers sync, and file, Git, and OCI sources load. Readiness fails. |
| Ready | Every source has loaded, and the server published a policy snapshot. Readiness passes. |
| Degraded | A source failed after the server was ready. The server keeps serving the last known good snapshot, and readiness keeps passing. |
| Draining | The server received `SIGTERM`. Readiness fails, the server keeps serving for `--drain-delay`, and then it shuts down gracefully within `--shutdown-timeout`. |

Until the server is ready, it rejects authorization requests so that your gateway's failure mode applies:

- The Envoy server returns the gRPC status `UNAVAILABLE` from `Check`, and the `grpc.health.v1.Health` service reports `NOT_SERVING`.
- The HTTP server returns `503 Service Unavailable`.

The probes server reports readiness on `/readyz` and liveness on `/livez`.

## Policy snapshots

The server evaluates every request against an immutable, versioned snapshot of its policies. It rebuilds the snapshot in the background when a policy or exception changes, and every 30 seconds. It never loads or compiles policies on the request path.

When a policy fails to compile, the server excludes that policy from the snapshot, logs the error, and sets the `authz_policy_compile_errors` metric for it. The other policies keep working. To keep the server from becoming ready instead, set `--strict`. After the server is ready, `--strict` keeps the last known good snapshot when any policy fails to compile.

## Requests that match no policy

`--default-decision` sets the decision for a request that no policy matches. That includes a request whose only matching policy is skipped by a policy exception.

| Value | Envoy | HTTP |
|---|---|---|
| `allow` | `OK` | `200` |
| `deny` | `PERMISSION_DENIED` with HTTP `403` | `403` |

The binary defaults to `allow` for backward compatibility. The Helm chart defaults to `deny`.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--default-decision` | `allow` | Decision for requests that match no policy (`allow` or `deny`). |
| `--min-policies` | `0` | Minimum number of policies that must load before the server becomes ready. After the server is ready, a refresh that loads fewer policies keeps the last known good snapshot. |
| `--strict` | `false` | Treat any policy compile error as a failed load instead of excluding the failing policy. |
| `--drain-delay` | `0s` | Time to keep serving after `SIGTERM` while readiness fails. |
| `--shutdown-timeout` | `10s` | Maximum time to wait for in-flight requests during a graceful shutdown. |

In the Helm chart, set these flags with `config.defaultDecision`, `config.minPolicies`, `config.strict`, `config.drainDelay`, and `config.shutdownTimeout`. Keep `authzServer.pod.terminationGracePeriodSeconds` greater than the drain delay plus the shutdown timeout.

## Metrics

| Metric | Description |
|---|---|
| `authz_server_phase{phase}` | `1` for the current phase, `0` for the others. |
| `authz_policy_snapshot_version` | Version of the current policy snapshot. |
| `authz_policy_snapshot_policies` | Number of policies in the current snapshot. |
| `authz_policy_snapshot_timestamp_seconds` | Unix time at which the current snapshot was published. |
| `authz_policy_snapshot_refresh_errors_total` | Refreshes that failed and kept the last known good snapshot. |
| `authz_policy_compile_errors{policy}` | `1` for each policy that failed to compile and is excluded. |
| `authz_decisions_total{decision="unavailable"}` | Requests rejected because the server wasn't ready. |
