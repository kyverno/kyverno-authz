# Programmability

The Kyverno Authz server provides programmability through CEL (Common Expression Language) expressions that allow you to transform request and response attributes dynamically.

## Overview

Two flags enable request and response transformation:

- **`--input-expression`**: Transforms incoming requests before authorization
- **`--output-expression`**: Transforms outgoing responses after authorization

Both flags accept CEL expressions that take a specific input type and evaluate to the same type.

## Input Expression

### Purpose

The input expression transforms incoming requests before they are processed by the authorization engine.

### Input/Output Type

[http.CheckRequest](../../cel-extensions/http.md#httpcheckrequest)

### Use Cases

- Modify request headers
- Extract information from custom headers
- Transform request attributes
- Normalize request data

### Example

```cel
http.CheckRequest{
  attributes: http.CheckRequestAttributes{
    method: object.attributes.Header("x-original-method")[0],
    header: object.attributes.header,
    host: url(object.attributes.Header("x-original-url")[0]).getHostname(),
    scheme: url(object.attributes.Header("x-original-url")[0]).getScheme(),
    path: url(object.attributes.Header("x-original-url")[0]).getEscapedPath(),
    query: url(object.attributes.Header("x-original-url")[0]).getQuery(),
    body: object.attributes.body,
    fragment: "todo",
  }
}
```

This example demonstrates how to use the `url` library to extract information from `x-original-xxx` headers and reconstruct the request attributes.

## Output Expression

### Purpose

The output expression transforms responses before they are sent back to the client.

### Input Type

[http.CheckResponse](../../cel-extensions/http.md#httpcheckresponse)

### Output Type

[httpserver.HttpResponse](../../cel-extensions/httpserver.md#httpresponse)

### Use Cases

- Modify response status codes
- Add or modify response headers
- Customize response body
- Add authentication metadata

### Example

```cel
has(object.ok)
  ? httpserver.HttpResponse{ status: 200 }
  : object.denied.reason == "Unauthorized"
      ? httpserver.HttpResponse{ status: 401, body: bytes(object.denied.reason) }
      : httpserver.HttpResponse{ status: 403, body: bytes(object.denied.reason) }
```

### Modifiable Fields

- **`status`**: HTTP status code
- **`body`**: Response body (as bytes)
- **`header`**: Response headers (map of string arrays)

## Configuration

Input and output expressions can be specified when deployed with Helm using the `config.http` stanza:

```bash
# deploy the kyverno authz server
helm install kyverno-authz-server                                       \
  --namespace kyverno --create-namespace                                \
  --wait                                                                \
  --repo https://kyverno.github.io/kyverno-authz kyverno-authz-server   \
  --values - <<EOF
config:
  type: http
  http:
    # controls input expression
    inputExpression: >-
      http.CheckRequest{
        attributes: http.CheckRequestAttributes{
          method: object.attributes.Header("x-original-method")[0],
          header: object.attributes.header,
          host: url(object.attributes.Header("x-original-url")[0]).getHostname(),
          scheme: url(object.attributes.Header("x-original-url")[0]).getScheme(),
          path: url(object.attributes.Header("x-original-url")[0]).getEscapedPath(),
          query: url(object.attributes.Header("x-original-url")[0]).getQuery(),
          fragment: "todo",
        }
      }
    # controls output expression
    outputExpression: >-
      has(object.ok)
        ? httpserver.HttpResponse{ status: 200 }
        : object.denied.reason == "Unauthorized"
            ? httpserver.HttpResponse{ status: 401, body: bytes(object.denied.reason) }
            : httpserver.HttpResponse{ status: 403, body: bytes(object.denied.reason) }
EOF
```
