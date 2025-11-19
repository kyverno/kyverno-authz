# Getting Started

## How It Works

### Envoy Integration

Connects with [Envoy’s External Authorization filter](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter.html) via gRPC.

Envoy sends authorization requests to the Kyverno Authz Server, which evaluates policies and returns allow/deny decisions.

![Architecture Overview](../schemas/overview.svg)

### HTTP Authorization

Runs as a programmable HTTP server that evaluates requests directly and returns a decision — ideal for ingress controllers or standalone services.

![Architecture Overview](../schemas/overview-2.svg)

## Get Started

- **[Envoy Hello World](../hello-world/envoy.md)** – Introduction to the Envoy Authz Server
- **[HTTP Hello World](../hello-world/http.md)** – Introduction to the HTTP Authz Server
