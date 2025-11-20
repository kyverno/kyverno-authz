# Configuration

## Policy sources

The Kyverno Authz Server supports various policy sources, see [Policy Sources](../../quick-start/policy-sources.md).

You can specify policy sources when deploying with Helm using the `config.sources` stanza:

```bash
# deploy the kyverno authz server
helm install kyverno-authz-server                                       \
  --namespace kyverno --create-namespace                                \
  --wait                                                                \
  --repo https://kyverno.github.io/kyverno-authz kyverno-authz-server   \
  --values - <<EOF
config:
  type: envoy
  sources:
    # controls the kube policy source
    kube: false
    # controls external policy sources
    external:
    - file:///data/kyverno-authz-server
EOF
```

## GRPC address and network

GRPC address and network can be specified when deployed with Helm using the `config.grpc` stanza:

```bash
# deploy the kyverno authz server
helm install kyverno-authz-server                                       \
  --namespace kyverno --create-namespace                                \
  --wait                                                                \
  --repo https://kyverno.github.io/kyverno-authz kyverno-authz-server   \
  --values - <<EOF
config:
  type: envoy
  grpc:
    # controls the grpc network
    network: tcp
    # controls the grpc address
    address: :9081
EOF
```

## Image pull secrets

You can specify image pull secrets to be used by the authz server when pulling OCI images containing policies from a registry.

Additionally you can allow pulling images from insecure registries.


```bash
# deploy the kyverno authz server
helm install kyverno-authz-server                                       \
  --namespace kyverno --create-namespace                                \
  --wait                                                                \
  --repo https://kyverno.github.io/kyverno-authz kyverno-authz-server   \
  --values - <<EOF
config:
  type: envoy
  # controls how to proceed with insecure registries
  allowInsecureRegistry: false
  # add secrets for pulling images from insecure registries
  imagePullSecrets:
  - secret-name
EOF
```
