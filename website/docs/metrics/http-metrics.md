# HTTP Server Metrics

The following Prometheus metrics are exposed by the HTTP Authorization Server:

## Metrics

### `authz_http_server_validating_requests`

**Type:** Counter

**Description:** Tracks the total number of HTTP authorization requests.

**Labels:**

| Label | Description |
|-------|-------------|
| `method` | HTTP method of the request (e.g., GET, POST, PUT, DELETE) |
| `host` | Target host of the HTTP request |
| `path` | URL path of the HTTP request |
| `schema` | HTTP scheme of the request (http or https) |
| `status` | Authorization status of the response (ok or denied) |

---

### `authz_http_server_validating_request_errors`

**Type:** Counter

**Description:** Tracks the total number of errors encountered during HTTP authorization requests.

**Labels:**

| Label | Description |
|-------|-------------|
| `method` | HTTP method of the request (e.g., GET, POST, PUT, DELETE) |
| `host` | Target host of the HTTP request |
| `path` | URL path of the HTTP request |
| `schema` | HTTP scheme of the request (http or https) |

---

### `authz_http_server_validating_requests_duration_seconds`

**Type:** Histogram

**Description:** Measures the latency (in seconds) of HTTP authorization requests.

**Labels:**

| Label | Description |
|-------|-------------|
| `method` | HTTP method of the request (e.g., GET, POST, PUT, DELETE) |
| `host` | Target host of the HTTP request |
| `path` | URL path of the HTTP request |
| `schema` | HTTP scheme of the request (http or https) |
| `status` | Authorization status of the response (ok or denied) |