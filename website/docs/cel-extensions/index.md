# CEL extensions

The CEL engine used to evaluate variables and authorization rules has been extended with various libraries. Each library has a different scope and purpose.

Some libraries are specific to `Envoy` or `HTTP` while others are common to both Authz Server types.

## Kyverno Authz libraries

| Lib | Envoy Policy | HTTP Policy | HTTP Server |
|:---|:---:|:---:|:---:|
| [Envoy](./envoy.md) | :white_check_mark: | | |
| [Http](./http.md) | | :white_check_mark: | :white_check_mark: |
| [Http Server](./httpserver.md) | | | :white_check_mark: |
| [Jwk](./jwk.md) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Jwt](./jwt.md) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Json](./json.md) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Mcp](./mcp.md) | :white_check_mark: | :white_check_mark: | :white_check_mark: |

## Common libraries

The libraries below are common CEL extensions enabled in the Kyverno Authz Server CEL engine.

| Lib | Envoy Policy | HTTP Policy | HTTP Server |
|:---|:---:|:---:|:---:|
| [Optional types](https://pkg.go.dev/github.com/google/cel-go/cel#OptionalTypes) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Cross type numeric comparisons](https://pkg.go.dev/github.com/google/cel-go/cel#CrossTypeNumericComparisons) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Bindings](https://pkg.go.dev/github.com/google/cel-go/ext#readme-bindings) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Encoders](https://pkg.go.dev/github.com/google/cel-go/ext#readme-encoders) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Lists](https://pkg.go.dev/github.com/google/cel-go/ext#readme-lists) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Math](https://pkg.go.dev/github.com/google/cel-go/ext#readme-math) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Protos](https://pkg.go.dev/github.com/google/cel-go/ext#readme-protos) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Sets](https://pkg.go.dev/github.com/google/cel-go/ext#readme-sets) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Strings](https://pkg.go.dev/github.com/google/cel-go/ext#readme-strings) | :white_check_mark: | :white_check_mark: | :white_check_mark: |

## Kubernetes libraries

The libraries below are imported from Kubernetes.

| Lib | Envoy Policy | HTTP Policy | HTTP Server |
|:---|:---:|:---:|:---:|
| [Lists](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-list-library) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Regex](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-regex-library) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [URL](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-url-library) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [IP](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-ip-address-library) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [CIDR](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-cidr-library) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Format](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-format-library) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Quantity](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-quantity-library) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Semver](https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-semver-library) | :white_check_mark: | :white_check_mark: | :white_check_mark: |

## Kyverno libraries

The libraries below are imported from Kyverno.

| Lib | Envoy Policy | HTTP Policy | HTTP Server |
|:---|:---:|:---:|:---:|
| [HTTP](https://kyverno.io/docs/policy-types/cel-libraries/#http-library) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [Image](https://kyverno.io/docs/policy-types/cel-libraries/#image-library) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| [ImageData](https://kyverno.io/docs/policy-types/cel-libraries/#imagedata-library) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
