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
  type: http
  sources:
    # controls the kube policy source
    kube: false
    # controls external policy sources
    external:
    - file:///data/kyverno-authz-server
EOF
```

## HTTP address

HTTP address can be specified when deployed with Helm using the `config.http.address` stanza:

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
    # controls the http address
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
  type: http
  # controls how to proceed with insecure registries
  allowInsecureRegistry: false
  # add secrets for pulling images from insecure registries
  imagePullSecrets:
  - secret-name
EOF
```

## Nested Request (experimental)

One of the flags you can pass to the HTTP authz server is the `--nestedRequest` boolean parameter, which controls a key behavior of the authz server.

-   If `false`, the authz server will run the policies against the request it receives directly. 
-   If `true`, it will expect that the request its receiving contains in its body the bytes of the request it should authenticate.

    i.e `curl -X POST <URL> -d {<THE-FULL-BYTES-OF-THE-REQUEST-TO-AUTHENTICATE>}`

For example, this is how a golang server would structure the request when `nestedRequest` is enabled:

```golang
// dump the request being processed
rawBytes, err := httputil.DumpRequest(r, true)
if err != nil {
  // handle error
}

// put the request in the body of the request to send to the authz server
req, err := http.NewRequest(
  http.MethodPost,
  "<URL>",
  io.NopCloser(bytes.NewReader(rawBytes)),
)
if err != nil {
  // handle error
}
```

Nested request processing can be specified when deployed with Helm using the `config.http.nestedRequest` stanza:

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
    # controls nested request processing
    nestedRequest: true
EOF
```
