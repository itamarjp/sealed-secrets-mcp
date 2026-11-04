# sealed-secrets-mcp

An [MCP](https://modelcontextprotocol.io) server that lets AI agents (Claude, Codex, Cursor, Grok, …)
turn Kubernetes Secrets into [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)
manifests **without ever seeing a plaintext value**.

The agent asks for a Secret, gets back a strict-scope `SealedSecret` resource as JSON, commits it
(as YAML or JSON), and opens the pull request. Your GitOps tool (Argo CD, Flux) applies it as usual.

## Security model

- **No plaintext leaves the server.** Tools return only ciphertext, key names and notes.
  Random values are generated server-side.
- **Read-only.** The server never creates, patches or deletes anything in the cluster. It only
  issues `GET` for single, named Secrets, and you choose which ones through RBAC.
- **No accidental rotation.** `generate_sealed_secret` refuses when the Secret already exists. An optional, separately scoped OAuth `rotate_sealed_secret` operation only returns ciphertext for an explicit exact-name allowlist; it never changes the cluster.
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
| `generate_sealed_secret` | Generates random values (`hex`, standard padded `base64`, `base64url` or `alnum`) for the requested keys and returns them sealed. Fails if the Secret exists. |
| `rotate_sealed_secret` | Optional OAuth `seal:rotate` scope, a separate per-Secret allowlist, and existing key names; generates and seals new values for the **same** Secret without changing the cluster. |

Tools return the `SealedSecret` resource as JSON, ready to save as YAML or JSON, plus a suggested
`file` name and `notes`. A note asks for the `sealedsecrets.bitnami.com/managed=true` annotation
when an existing Secret has to be adopted by the controller. Example:

```json
{
  "sealedSecret": {
    "apiVersion": "bitnami.com/v1alpha1",
    "kind": "SealedSecret",
    "metadata": { "name": "db", "namespace": "apps" },
    "spec": {
      "encryptedData": { "PASSWORD": "AgBy3i4OJSWK…" },
      "template": { "metadata": { "name": "db", "namespace": "apps" }, "type": "Opaque" }
    }
  },
  "file": "db.sealed.yaml"
}
```

If a ciphertext is damaged while copying, nothing leaks: the controller refuses to decrypt it and
reports the error on the SealedSecret.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `SEAL_AUDIENCE` | (required) | Public URL of the MCP endpoint, e.g. `https://seal.example.com/mcp`. Tokens are bound to it. |
| `SEAL_SIGNING_KEY_FILE` | `/etc/sealed-secrets-mcp/signing-key` | HMAC key, at least 32 bytes. |
| `SEAL_MAX_TTL` | `24h` | Longest token lifetime accepted. |
| `SEAL_CERT_URL` | `http://sealed-secrets-controller.kube-system.svc:8080/v1/cert.pem` | Controller public certificate. |
| `SEAL_LISTEN` | `:8080` | Listen address. `/mcp` is the endpoint; `/healthz` is the process liveness probe and `/readyz` checks Kubernetes API connectivity and the controller certificate. |
| `SEAL_KUBE_API` | in-cluster | API URL for local runs, e.g. `kubectl proxy` at `http://127.0.0.1:8001`. |

## Deploy

[`deploy/example.yaml`](deploy/example.yaml) has a minimal Deployment, Service and RBAC.
Create the signing key once (seal it too, if you keep the server's own config in Git):

```sh
kubectl -n sealed-secrets-mcp create secret generic sealed-secrets-mcp \
  --from-literal=signing-key="$(openssl rand -hex 32)"
```

Restrict the `Role`/`ClusterRole` with `resourceNames` to the Secrets agents may read.
Expose `/mcp` through your ingress with TLS. Keep `/healthz` and `/readyz` internal to the cluster.

The example Deployment uses `/healthz` for liveness and `/readyz` for readiness. `/readyz` returns 200 only when the Kubernetes API `/version` endpoint is reachable and the Sealed Secrets controller publishes a parseable, currently valid RSA certificate; otherwise it returns 503. The service account needs access to the non-resource URL `/version` if your cluster does not grant that access by default. Readiness does not require permission to list Secrets. Certificate rotation can cause transient 503 responses; probes retry automatically.

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

claude.ai (custom connector, OAuth through Pocket ID, needs `SEAL_AUTH_MODE=hybrid` or `pocketid`):

1. Pocket ID: create an OIDC client named `Claude` with callback URL
   `https://claude.ai/api/mcp/auth_callback`, restrict it to a group that holds only your user,
   and under **APIs** grant it `seal:existing` on the `https://seal.example.com/mcp` resource
   (`seal:rotate` too only if you want rotation from Claude). Pocket ID has no dynamic client
   registration, so this manual client is required.
2. claude.ai → Settings → Connectors → **Add custom connector**: URL `https://seal.example.com/mcp`;
   open **Advanced settings** and paste the Pocket ID Client ID and Client Secret.
3. Connect and sign in with your passkey. Only `seal_existing_secret` (and `rotate_sealed_secret`
   if granted) appears, limited to `SEAL_POCKET_ID_TARGET_NAMES`.

The 401 challenge on `/mcp` names `scope="seal:existing"`, so clients ask only for the read
scope; a client without the `seal:rotate` grant would otherwise be refused by Pocket ID with
`invalid_scope`.

To use `rotate_sealed_secret` from claude.ai, grant `seal:rotate` to the client in Pocket ID,
set `SEAL_POCKET_ID_CHALLENGE_ROTATE=true` (requires `SEAL_POCKET_ID_ROTATE_TARGET_NAMES`) so the
challenge names `scope="seal:existing seal:rotate"`, then reconnect the connector to get a new
token. Enable it only when **every** OAuth client of this resource holds both grants, otherwise
Pocket ID refuses that client's sign-in with `invalid_scope`.

ChatGPT: see [integration and Pocket ID/OAuth requirements](docs/chatgpt.md). The included `plugin.json` and `mcp.json` declare Pocket ID OAuth for ChatGPT. The optional `SEAL_AUTH_MODE=pocketid` resource-server mode validates audience-bound Pocket ID access tokens and restricts tools; deployment requires Pocket ID API/CIMD configuration and an explicit allowed user subject. Credential rotation requires an additional `seal:rotate` API permission and `SEAL_POCKET_ID_ROTATE_TARGET_NAMES` exact target names; see [ChatGPT rotation procedure](docs/chatgpt.md#explicit-oauth-secret-rotation-opt-in).

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
