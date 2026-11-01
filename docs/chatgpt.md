# ChatGPT integration

The server exposes **Streamable HTTP** at `https://seal.ispbrasil.com.br/mcp`. It currently uses **fixed short-lived bearer JWTs**, not OAuth.

## Important limitation

The ChatGPT **Add custom MCP server** web form currently offers OAuth or no authentication; **it does not accept a fixed API-key/bearer token**. Do not select "No authentication" and do not remove bearer verification from `/mcp` to make tool scanning pass. That would grant callers remote access to any Kubernetes Secrets allowed by the service account.

The included portable `plugin.json` + `mcp.json` describe the server and its `api_key` bearer authentication for plugin runtimes that support this mechanism. **Packaging is not a substitute for OAuth** and does not guarantee the ChatGPT web connector will install it.

For current ChatGPT web connectivity, deploy an OAuth 2.1 authorization-code + PKCE integration in front of the MCP endpoint (or implement it in the server) with an identity provider, protected-resource metadata, issuer discovery, resource-bound access tokens, token validation and per-user authorization. Do not publish or deploy an unauthenticated fallback. See [OpenAI authentication guidance](https://developers.openai.com/plugins/build/auth) and [custom MCP setup](https://developers.openai.com/api/docs/guides/custom-mcp-server).

## Existing compatible clients (fixed bearer)

Generate a scoped token from the running pod. **Never paste tokens into chat, commit them or put them in issue/PR logs.**

```sh
kubectl -n sealed-secrets-mcp exec deployment/sealed-secrets-mcp -- \
  sealed-secrets-mcp token --client codex --ttl 2h
```

Use the token only in the client application's private credential store. For Codex CLI, use `bearer_token_env_var` as described in the README. The portable plugin's `mcp.json` intentionally contains **no credentials**.

## KingP2P verification checklist

1. Confirm the server HTTPS endpoint is reachable and its certificate is valid.
2. Confirm the Kubernetes Role grants `get` on **only** the named `kingp2p-test/kingp2p-r2-pgbackrest` Secret.
3. Confirm unauthenticated `/mcp` requests return HTTP 401, and `/healthz` / `/readyz` are not exposed externally.
4. Authenticate through a supported OAuth integration before using ChatGPT web.
5. Call `seal_existing_secret` with `{"namespace":"kingp2p-test","name":"kingp2p-r2-pgbackrest"}`.
6. Confirm the returned `SealedSecret` is strict-scope and contains `encryptedData`, never `data`, `stringData` or plaintext.
7. Commit only ciphertext to the GitOps PR, with human review; don't enable deployment or automatic merge.

The MCP server itself is read-only. It does not create or deploy Kubernetes objects.
