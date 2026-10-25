# sealed-secrets-mcp

An [MCP](https://modelcontextprotocol.io) server that lets AI agents (Claude, Codex, Cursor, Grok, …)
turn Kubernetes Secrets into [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)
manifests **without ever seeing a plaintext value**.

The agent asks for a Secret, gets back a strict-scope `SealedSecret` YAML, commits it, and opens
the pull request. Your GitOps tool (Argo CD, Flux) applies it as usual.

## Security model

- **No plaintext leaves the server.** Tools return only ciphertext, key names and notes.
  Random values are generated server-side.
- **Read-only.** The server never creates, patches or deletes anything in the cluster. It only
  issues `GET` for single, named Secrets, and you choose which ones through RBAC.
- **No accidental rotation.** `generate_sealed_secret` refuses when the Secret already exists.
- **Short-lived tokens.** Clients authenticate with HS256 tokens that expire (24 h by default).
  Minting one requires the signing key, i.e. `kubectl exec` into the pod. Rotating the key
  revokes every token.
- **Strict scope only.** Ciphertext is bound to the Secret's namespace and name.
- **Audit log.** Every call is logged as JSON with the token's client name, never with values.

Encryption is a ~20-line reimplementation of `kubeseal`'s hybrid scheme (RSA-OAEP SHA-256 +
AES-256-GCM). CI decrypts the output with the official `kubeseal --recovery-unseal` to prove
compatibility.

## Tools

| Tool | What it does |
| --- | --- |
| `seal_existing_secret` | Reads a live Secret and returns it sealed, with the same values. Use it to move a manually created Secret into Git. |
| `generate_sealed_secret` | Generates random values (`hex`, `base64url` or `alnum`) for the requested keys and returns them sealed. Fails if the Secret exists. |

Both return `manifest`, its `sha256` (so the agent can check the committed file is intact),
a suggested `file` name, the `keys`, and `notes` such as the
`sealedsecrets.bitnami.com/managed=true` annotation needed to adopt an existing Secret.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `SEAL_AUDIENCE` | (required) | Public URL of the MCP endpoint, e.g. `https://seal.example.com/mcp`. Tokens are bound to it. |
| `SEAL_SIGNING_KEY_FILE` | `/etc/sealed-secrets-mcp/signing-key` | HMAC key, at least 32 bytes. |
| `SEAL_MAX_TTL` | `24h` | Longest token lifetime accepted. |
| `SEAL_CERT_URL` | `http://sealed-secrets-controller.kube-system.svc:8080/v1/cert.pem` | Controller public certificate. |
| `SEAL_LISTEN` | `:8080` | Listen address. `/mcp` is the endpoint, `/healthz` the probe. |
| `SEAL_KUBE_API` | in-cluster | API URL for local runs, e.g. `kubectl proxy` at `http://127.0.0.1:8001`. |

## Deploy

[`deploy/example.yaml`](deploy/example.yaml) has a minimal Deployment, Service and RBAC.
Create the signing key once (seal it too, if you keep the server's own config in Git):

```sh
kubectl -n sealed-secrets-mcp create secret generic sealed-secrets-mcp \
  --from-literal=signing-key="$(openssl rand -hex 32)"
```

Restrict the `Role`/`ClusterRole` with `resourceNames` to the Secrets agents may read.
Expose `/mcp` through your ingress with TLS.

## Tokens

```sh
kubectl -n sealed-secrets-mcp exec deploy/sealed-secrets-mcp -- \
  sealed-secrets-mcp token --client codex --ttl 24h
```

Use one client name per agent so the audit log tells them apart.

## Clients

Claude Code:

```sh
claude mcp add --transport http seal https://seal.example.com/mcp \
  --header "Authorization: Bearer $SEAL_MCP_TOKEN"
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.seal]
url = "https://seal.example.com/mcp"
bearer_token_env_var = "SEAL_MCP_TOKEN"
```

Cursor (`.cursor/mcp.json`):

```json
{ "mcpServers": { "seal": {
  "url": "https://seal.example.com/mcp",
  "headers": { "Authorization": "Bearer ${env:SEAL_MCP_TOKEN}" } } } }
```

Grok (xAI API remote MCP tool): pass the URL as `server_url` and the token as `authorization`.

claude.ai custom connectors support fixed request headers only as a beta for some organizations;
OAuth is not implemented here.

## Development

```sh
go test ./...                      # add kubeseal to PATH to run the compatibility test
kubectl proxy &
SEAL_KUBE_API=http://127.0.0.1:8001 SEAL_AUDIENCE=http://127.0.0.1:8080/mcp \
SEAL_SIGNING_KEY_FILE=./key SEAL_CERT_URL=http://127.0.0.1:8001/api/v1/namespaces/kube-system/services/http:sealed-secrets-controller:8080/proxy/v1/cert.pem \
  go run . serve
```

## License

Apache-2.0
