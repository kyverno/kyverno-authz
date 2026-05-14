# kube-agent external auth integration

This guide wires `kyverno-authz` into the [kube-agentic-networking (KAN)](https://kube-agentic-networking.sigs.k8s.io/) external-auth quickstart as the external authorizer. It covers:

1. Running the KAN external-auth quickstart to create the cluster and agent infrastructure.
2. Installing `kyverno-authz` on the same cluster with a static webhook certificate.
3. Applying policies and validating end-to-end authorization enforcement.

The verified install uses a local build from the `main` branch (with the validation-webhook fix from PR #218), installed from the local Helm chart in Envoy mode with a self-managed (static) webhook certificate.

## Part 1: Set up KAN with the external-auth quickstart

Clone the KAN repository:

```bash
git clone https://github.com/kubernetes-sigs/kube-agentic-networking.git
cd kube-agentic-networking
```

Run the external-auth quickstart script with your chosen LLM provider (Option 3, Ollama, requires no API token):

```bash
# Ensure Ollama is running locally with a model pulled, e.g.:
#   ollama pull qwen2.5:7b
bash site-src/guides/external-auth-quickstart/run-external-auth-quickstart.sh --ollama
```

For other LLM providers:

```bash
# HuggingFace
export HF_TOKEN=<your-huggingface-token>
bash site-src/guides/external-auth-quickstart/run-external-auth-quickstart.sh

# Gemini
export GOOGLE_API_KEY=<your-api-key>
bash site-src/guides/external-auth-quickstart/run-external-auth-quickstart.sh --gemini
```

See the [KAN external-auth quickstart](https://kube-agentic-networking.sigs.k8s.io/guides/external-auth-quickstart/) for full prerequisites and details.

When the script completes, the following resources exist in the `kind-kan-quickstart` cluster:

- Namespace `quickstart-ns` with `adk-agent-sa` service account
- `XBackend` named `remote-mcp-backend`
- Agent deployment `adk-agent` with `adk-agent-svc` service (port 80 → 8080)
- KAN gateway with a MetalLB-assigned LoadBalancer IP (e.g. `192.168.97.200`) on port `10001`
- Port-forward to agent UI running at `http://localhost:8081/dev-ui/?app=mcp_agent`


## Part 2: Install kyverno-authz on the existing cluster

### Step 1: Install the Kyverno policy CRDs (`ValidatingPolicy` and `PolicyException`)

```bash
kubectl apply \
  -f https://raw.githubusercontent.com/kyverno/kyverno/refs/heads/main/config/crds/policies.kyverno.io/policies.kyverno.io_validatingpolicies.yaml
kubectl apply \
  -f https://raw.githubusercontent.com/kyverno/kyverno/refs/heads/main/config/crds/policies.kyverno.io/policies.kyverno.io_policyexceptions.yaml
```

### Step 2: Generate a self-signed webhook certificate

```bash
openssl req -new -x509 \
  -subj "/CN=kyverno-authz-server-validation.kyverno.svc" \
  -addext "subjectAltName = DNS:kyverno-authz-server-validation.kyverno.svc" \
  -nodes -newkey rsa:4096 -keyout tls.key -out tls.crt
```

### Step 3: Build and install from the local `kyverno-authz` chart (Envoy, static certs)

Build a local image and load it into the kind cluster:

```bash
TAG="local-$(date +%Y%m%d%H%M%S)"
make ko-build KO_REGISTRY=ko.local KO_TAGS=$TAG
kind load docker-image "ko.local/github.com/kyverno/kyverno-authz:$TAG" --name kan-quickstart
```

Install from the local chart with the image override and static certs:

```bash
helm upgrade --install kyverno-authz-server                                    \
  --namespace kyverno --create-namespace                                       \
  --wait                                                                       \
  charts/kyverno-authz-server                                                  \
  --set-file validatingWebhookConfiguration.certificates.static.crt=tls.crt    \
  --set-file validatingWebhookConfiguration.certificates.static.key=tls.key    \
  --set authzServer.container.image.registry=ko.local                          \
  --set authzServer.container.image.repository=github.com/kyverno/kyverno-authz \
  --set authzServer.container.image.tag=$TAG                                   \
  --set validatingWebhookConfiguration.container.image.registry=ko.local       \
  --set validatingWebhookConfiguration.container.image.repository=github.com/kyverno/kyverno-authz \
  --set validatingWebhookConfiguration.container.image.tag=$TAG                \
  --values - <<EOF
config:
  type: envoy
EOF
```

Verify both deployments are running:

```bash
kubectl -n kyverno get deploy,po,svc,validatingwebhookconfiguration
```

Expected result:

- `deployment/kyverno-authz-server` is `1/1`.
- `deployment/kyverno-authz-server-validation` is `1/1`.

### Step 4: Apply the kube-agent integration manifests

```bash
kubectl apply \
  -f .manifests/integrations/kube-agent/10-validatingpolicy-envoy-deny-all.yaml
kubectl apply \
  -f .manifests/integrations/kube-agent/20-xaccesspolicy-external-auth-kyverno-authz.yaml
```

## Part 3: Quick validation

### Deploy a test pod with mTLS identity

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: e2e-tester
  namespace: quickstart-ns
spec:
  serviceAccountName: adk-agent-sa
  containers:
  - name: tester
    image: curlimages/curl:latest
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: agent-identity-mtls
      mountPath: /run/agent-identity-mtls
      readOnly: true
  volumes:
  - name: agent-identity-mtls
    projected:
      sources:
      - clusterTrustBundle:
          signerName: kube-agentic-networking.sigs.k8s.io/identity
          labelSelector:
            matchLabels:
              "kube-agentic-networking.sigs.k8s.io/canarying": "live"
              "kube-agentic-networking.sigs.k8s.io/workload-trust-domain": "cluster.local"
              "kube-agentic-networking.sigs.k8s.io/peer-trust-domain": "cluster.local"
          path: cluster.local.trust-bundle.pem
      - podCertificate:
          signerName: kube-agentic-networking.sigs.k8s.io/identity
          keyType: ECDSAP256
          credentialBundlePath: credential-bundle.pem
EOF
kubectl -n quickstart-ns wait pod/e2e-tester --for=condition=Ready --timeout=120s
```

### Test 1: Deny-all policy active

```bash
kubectl -n quickstart-ns exec e2e-tester -- \
  curl -sk \
  --cert /run/agent-identity-mtls/credential-bundle.pem \
  --key /run/agent-identity-mtls/credential-bundle.pem \
  -w "HTTP:%{http_code}\n" \
  -X POST "https://192.168.97.200:10001/remote/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"echo","arguments":{"message":"test"}}}'
```

**Expected result:** HTTP 200 with JSON response `{"error":{"code":403,"message":"Access to this tool is forbidden."},...}` — the request reaches the kyverno-authz ext_authz filter which returns 403 denial.

> **Note on HTTP 200 + JSON-RPC 403:** The MCP protocol wraps authorization failures as JSON-RPC error objects inside an HTTP 200 response. This is the expected behavior from the KAN gateway's Envoy external auth filter.

### Test 2: Switch to allow-all policy

```bash
kubectl delete validatingpolicy kan-remote-mcp-deny-all
kubectl apply \
  -f .manifests/integrations/kube-agent/11-validatingpolicy-envoy-allow-all.yaml
sleep 5
```

Retry with MCP `Accept` headers:

```bash
kubectl -n quickstart-ns exec e2e-tester -- \
  curl -sk \
  --cert /run/agent-identity-mtls/credential-bundle.pem \
  --key /run/agent-identity-mtls/credential-bundle.pem \
  -w "HTTP:%{http_code}\n" \
  -X POST "https://192.168.97.200:10001/remote/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"echo","arguments":{"message":"test"}}}'
```

**Expected result:** HTTP 200 with backend response (for example `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Unknown tool: echo"}],"isError":true}}`). This confirms kyverno-authz is no longer denying and traffic reaches MCP backend logic.
