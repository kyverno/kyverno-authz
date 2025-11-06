---
title: "kyverno-authz serve sidecar-injector"
slug: "kyverno-authz_serve_sidecar-injector"
description: "CLI reference for kyverno-authz serve sidecar-injector"
---

## kyverno-authz serve sidecar-injector

Start the Kubernetes mutating webhook injecting Kyverno Authz Server sidecars into pod containers

```
kyverno-authz serve sidecar-injector [flags]
```

### Options

```
      --address string       Address to listen on (default ":9443")
      --cert-file string     File containing tls certificate
      --config-file string   File containing the sidecar config
  -h, --help                 help for sidecar-injector
      --key-file string      File containing tls private key
```

### SEE ALSO

* [kyverno-authz serve](kyverno-authz_serve.md)	 - Run Kyverno Authz servers

