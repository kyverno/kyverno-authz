# Ingress Nginx

[Ingress NGINX](https://kubernetes.github.io/ingress-nginx/) is an open source Ingress controller for Kubernetes that uses [NGINX](https://www.nginx.com/) as a reverse proxy and load balancer. It provides a flexible and powerful way to manage external access to services in a Kubernetes cluster.

This tutorial shows how Ingress NGINX can be configured to delegate authorization decisions to the Kyverno Authz Server using the external authentication feature.

## Setup

### Prerequisites

- A Kubernetes cluster
- [Helm](https://helm.sh/) to install Ingress NGINX and the Kyverno Authz Server
- [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl) to interact with the cluster

### Setup a cluster (optional)

If you don't have a cluster at hand, you can create a local one with [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation).

```bash
KIND_IMAGE=kindest/node:v1.34.0

# create cluster
kind create cluster --image $KIND_IMAGE --wait 1m
```

### Install Ingress NGINX

First we need to install Ingress NGINX in the cluster.

```bash
# install ingress-nginx
helm install ingress-nginx                                        \
  --namespace ingress-nginx --create-namespace                    \
  --wait                                                          \
  --repo https://kubernetes.github.io/ingress-nginx ingress-nginx \
  --values - <<EOF
controller:
  service:
    type: ClusterIP
EOF
```

The `controller.service.type=ClusterIP` setting is used because the kind cluster created in the previous step doesn't come with load balancer support. For production environments or cloud providers with load balancer support, you can omit this setting or use `LoadBalancer`.

### Deploy a sample application

Httpbin is a well-known application that can be used to test HTTP requests and helps to show quickly how we can play with the request and response attributes.

```bash
# create the demo namespace
kubectl create ns demo

# deploy the httpbin application
kubectl apply \
  -n demo     \
  -f https://raw.githubusercontent.com/istio/istio/master/samples/httpbin/httpbin.yaml
```

### Create an Ingress with External Authentication

Now create a separate Ingress resource for `myapp.com` with external authentication enabled.

```bash
# create ingress with external auth for myapp.com
kubectl apply -n demo -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myapp
  annotations:
    nginx.ingress.kubernetes.io/auth-method: POST
    nginx.ingress.kubernetes.io/auth-url: >-
      http://kyverno-authz-server.kyverno.svc.cluster.local:9081/
spec:
  ingressClassName: nginx
  rules:
  - host: myapp.com
    http:
      paths:
      - path: /anything
        pathType: Prefix
        backend:
          service:
            name: httpbin
            port:
              number: 8000
EOF
```

### Deploy cert-manager

The Kyverno Authz Server comes with a validation webhook and needs a certificate to let the api server call into it.

Let's deploy `cert-manager` to manage the certificate we need.

Install cert-manager:

```bash
# install cert-manager
helm install cert-manager                         \
  --namespace cert-manager --create-namespace     \
  --wait                                          \
  --repo https://charts.jetstack.io cert-manager  \
  --values - <<EOF
crds:
  enabled: true
EOF
```

Create a certificate issuer:

```bash
# create a certificate issuer
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
EOF
```

For more certificate management options, refer to [Certificates management](../quick-start/kube-install.md#certificates-management).

### Install Kyverno ValidatingPolicy CRD

Before deploying the Kyverno Authz Server, we need to install the Kyverno ValidatingPolicy CRD.

```bash
kubectl apply \
  -f https://raw.githubusercontent.com/kyverno/kyverno/refs/heads/main/config/crds/policies.kyverno.io/policies.kyverno.io_validatingpolicies.yaml
```

### Deploy the Kyverno Authz Server

Now we can deploy the Kyverno Authz Server.

```bash
# deploy the kyverno authz server
helm install kyverno-authz-server                                     \
  --namespace kyverno --create-namespace                              \
  --wait                                                              \
  --repo https://kyverno.github.io/kyverno-authz kyverno-authz-server \
  --values - <<EOF
config:
  type: http
  http:
    nestedRequest: false
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
    outputExpression: >-
      has(object.ok)
        ? httpserver.HttpResponse{ status: 200 }
        : object.denied.reason == "Unauthorized"
            ? httpserver.HttpResponse{ status: 401, body: bytes(object.denied.reason) }
            : httpserver.HttpResponse{ status: 403, body: bytes(object.denied.reason) }
validatingWebhookConfiguration:
  certificates:
    certManager:
      issuerRef:
        group: cert-manager.io
        kind: ClusterIssuer
        name: selfsigned-issuer
EOF
```

### Create a Kyverno ValidatingPolicy

In summary the policy below does the following:

- Checks that the JWT token is valid
- Checks that the action is allowed based on the token payload `role` and the request path

```bash
kubectl apply -f - <<EOF
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: demo
spec:
  evaluation:
    mode: HTTP
  failurePolicy: Fail
  variables:
  - name: authorizationlist
    expression: object.attributes.Header("authorization")
  - name: authorization
    expression: >
      size(variables.authorizationlist) == 1
        ? variables.authorizationlist[0].split(" ")
        : []
  - name: token
    expression: >
      size(variables.authorization) == 2 && variables.authorization[0].lowerAscii() == "bearer"
        ? jwt.Decode(variables.authorization[1], "secret")
        : null
  validations:
    # request not authenticated -> 401
  - expression: >
      variables.token == null || !variables.token.Valid
        ? http.Denied("Unauthorized").Response()
        : null
    # request authenticated but not admin role -> 403
  - expression: >
      variables.token.Claims.?role.orValue("") != "admin"
        ? http.Denied("Forbidden").Response()
        : null
    # request authenticated and admin role -> 200
  - expression: >
      http.Allowed().Response()
EOF
```

## Testing

At this point we have deployed and configured Ingress NGINX, the Kyverno Authz Server, a sample application, a protected ingress, and the validating policy.


### Start an in-cluster shell

Let's start a pod in the cluster with a shell to call into the sample application.

```bash
# run an in-cluster shell
kubectl run -i -t busybox --image=alpine --restart=Never -n demo
```

### Install curl

We will use curl to call into the sample application but it's not installed in our shell, let's install it in the pod.

```bash
# install curl
apk add curl
```

### Call into the sample application

Now we can send request to the sample application and verify the result.

For convenience, we will store Alice’s and Bob’s tokens in environment variables.

Here Bob is assigned the admin role and Alice is assigned the guest role.

```bash
export ALICE_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIyNDEwODE1MzksIm5iZiI6MTUxNDg1MTEzOSwicm9sZSI6Imd1ZXN0Iiwic3ViIjoiWVd4cFkyVT0ifQ.ja1bgvIt47393ba_WbSBm35NrUhdxM4mOVQN8iXz8lk"
export BOB_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIyNDEwODE1MzksIm5iZiI6MTUxNDg1MTEzOSwicm9sZSI6ImFkbWluIiwic3ViIjoiWVd4cFkyVT0ifQ.veMeVDYlulTdieeX-jxFZ_tCmqQ_K8rwx2OktUHv5Z0"
```

Calling without a JWT token will return `401`:

```bash
curl -s -w "\nhttp_code=%{http_code}"                     \
  ingress-nginx-controller.ingress-nginx/anything/api/v1  \
  -H "Host: myapp.com"
```

Calling with Alice’s JWT token will return `403`:

```bash
curl -s -w "\nhttp_code=%{http_code}"                     \
  ingress-nginx-controller.ingress-nginx/anything/api/v1  \
  -H "Host: myapp.com"                                    \
  -H "authorization: Bearer $ALICE_TOKEN"
```

Calling with Bob’s JWT token will return `200`:

```bash
curl -s -w "\nhttp_code=%{http_code}"                     \
  ingress-nginx-controller.ingress-nginx/anything/api/v1  \
  -H "Host: myapp.com"                                    \
  -H "authorization: Bearer $BOB_TOKEN"
```

## Wrap Up

Congratulations on completing the tutorial!

This tutorial demonstrated how to configure Ingress NGINX to utilize the Kyverno Authz Server as an external authorization service.

Additionally, the tutorial provided an example policy to decode a JWT token and make a decision based on it.
