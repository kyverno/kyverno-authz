# Http Server library

The `httpserver` library provides types and functions for manipulating HTTP requests and responses in CEL expressions.

It allows an HTTP server to pre-process an incoming request and create an HTTP response from policy evaluation results.

## Types

### `httpserver.HttpResponse`

Represents the HTTP response that will be sent back to the caller.

| Field | CEL Type | Description |
|---|---|---|
| `status` | `int` | Status code |
| `header` | `map<string, list<string>>` | Response headers (multi-value map) |
| `body` | `bytes` | Response body as raw bytes |

**Example:**

```cel
has(object.ok)
  ? httpserver.HttpResponse{ status: 200 }
  : object.denied.reason == "Unauthorized"
      ? httpserver.HttpResponse{ status: 401, body: bytes(object.denied.reason) }
      : httpserver.HttpResponse{ status: 403, body: bytes(object.denied.reason) }
```
