# Envoy Server Metrics

The following Prometheus metrics are exposed by the Envoy Authorization Server:

## Metrics

### `authz_envoy_server_validating_requests`

**Type:** Counter

**Description:** Tracks the total number of Envoy authorization requests.

**Labels:**

| Label | Description |
|-------|-------------|
| `method` | HTTP method of the request (e.g., GET, POST, PUT, DELETE) |
| `host` | Target host of the HTTP request |
| `path` | URL path of the HTTP request |
| `schema` | HTTP scheme of the request (http or https) |
| `status` | HTTP status code of the response |

---

### `authz_envoy_server_validating_request_errors`

**Type:** Counter

**Description:** Tracks the total number of errors encountered during Envoy authorization requests.

**Labels:**

| Label | Description |
|-------|-------------|
| `method` | HTTP method of the request (e.g., GET, POST, PUT, DELETE) |
| `host` | Target host of the HTTP request |
| `path` | URL path of the HTTP request |
| `schema` | HTTP scheme of the request (http or https) |

---

### `authz_envoy_server_validating_requests_duration_seconds`

**Type:** Histogram

**Description:** Measures the latency (in seconds) of Envoy authorization requests.

**Labels:**

| Label | Description |
|-------|-------------|
| `method` | HTTP method of the request (e.g., GET, POST, PUT, DELETE) |
| `host` | Target host of the HTTP request |
| `path` | URL path of the HTTP request |
| `schema` | HTTP scheme of the request (http or https) |
| `status` | HTTP status code of the response |