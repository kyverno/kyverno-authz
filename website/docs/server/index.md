# Authz Server

The **Kyverno Authz Server** provides programmable and flexible, policy-based authorization for **Envoy proxies** and **HTTP services**.

It uses **Kyverno policies** written in **CEL (Common Expression Language)** to deliver fine-grained, context-aware access control and make a decision given an input request description.

!!! info
    The Kyverno Authz Server runs seamlessly in Kubernetes or as a standalone service outside Kubernetes environments.

## Key Capabilities

- **Dual-mode operation** – Works with Envoy (gRPC) or standalone HTTP services
- **Programmable** – Adapts to the underlying protocol (NGINX, Traefik, ...)
- **Policy-driven authorization** – Write policies using CEL with your decision logic for fast evaluation
- **External data integration** – Query HTTP services, fetch Kubernetes resources or OCI images data for decision-making
- **Lightweight sidecar model** – Low-latency local enforcement with centralized policy management

## Running Modes

- [Envoy Support](./envoy/index.md)
- [HTTP Support](./http/index.md)