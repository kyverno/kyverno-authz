# HTTP Authz Server

This example demonstrates how to run and test the **Kyverno Authorization Server** in **HTTP** mode using a simple local policy and HTTP requests.

It helps you understand how the server evaluates incoming requests and applies defined validation rules.

## Prerequisites

Before you begin, make sure you have:

- [Docker](https://www.docker.com) installed and working.
- [curl](https://curl.se) for sending requests to the authz server.

!!! tip
    You **do not need a Kubernetes cluster** for this tutorial — the server runs locally and loads policies directly from files.

## Step 1: Create a Policy

Start by creating a simple **ValidatingPolicy**.

Save the following policy as `quick-start.yaml` in your working directory:

```yaml
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: policy
spec:
  evaluation:
    mode: HTTP
  matchConditions:
  - name: match-host
    expression: |
      object.attributes.host == "http-srv.app"
  validations:
  - expression: >
      http.Denied("not allowed").Response()
```

This policy specifies that any request where the host field equals `http-srv.app` will be denied with the message `"not allowed"`.

## Step 2: Run the HTTP Authz Server

You can use Docker to start the Kyverno Authz Server and load the policy created above.

Run the following command from your terminal:

```bash
docker run --rm                                               \
  -p 9081:9081                                                \
  -v ${PWD}/quick-start.yaml:/data/policies/quick-start.yaml  \
  ghcr.io/kyverno/kyverno-authz:latest                        \
  serve http authz-server --kube-policy-source=false          \
  --external-policy-source file://data/policies
```

!!! info
    - The flag --external-policy-source tells the server to load policies from file://data/policies.
    - Port 9081 is exposed for HTTP requests.
    - TLS certificates are not required for this example.

Once the container starts, you should see output similar to this:

```
2025-11-17T12:19:55+01:00       INFO    Using namespace 'default' - consider setting explicit namespace
2025-11-17T12:19:55+01:00       INFO    HTTP Server starting... {"address": ":9081", "cert": "", "key": ""}
```

This confirms the server is running and listening on port `9081`.

## Step 3: Send Requests to the Server

Now that the server is running, you can send test requests to observe how the policy behaves.

### Example 1 — Request without a Host header

```bash
curl -s -i -X POST http://127.0.0.1:9081
```

You should receive a response similar to:

```
HTTP/1.1 200 OK
Date: Wed, 19 Nov 2025 14:41:06 GMT
Content-Length: 0
```

This request does not match the condition `object.attributes.host == "http-srv.app"`.
The policy will not be triggered, so the request should succeed or be allowed.

### Example 2 — Request with a matching Host header

```bash
curl -s -i -X POST http://127.0.0.1:9081 -H "Host: http-srv.app"
```

In this case, the condition is met and the policy denies the request.

You should receive a response similar to:

```
HTTP/1.1 403 Forbidden
Date: Wed, 19 Nov 2025 14:44:53 GMT
Content-Length: 11
Content-Type: text/plain; charset=utf-8

not allowed
```

This indicates the policy was evaluated and the request was rejected according to your defined rule.

## Step 4: Summary

1.    Create a simple HTTP policy that denies requests based on the host
2.    Run the Kyverno Authz Server using Docker
3.    Send test requests and observe the server’s decision
