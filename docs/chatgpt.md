# ChatGPT integration

The server exposes **Streamable HTTP** at `https://seal.ispbrasil.com.br/mcp`. It currently uses **fixed short-lived bearer JWTs**, not OAuth.

## Important limitation

The ChatGPT **Add custom MCP server** web form currently offers OAuth or no authentication; **it does not accept a fixed API-key/bearer token**. Do not select "No authentication" and do not remove bearer verification from `/mcp` to make tool scanning pass. That would grant callers remote access to any Kubernetes Secrets allowed by the service account.

The included portable `plugin.json` + `mcp.json` describe the server and its `api_key` bearer authentication for plugin runtimes that support this mechanism. **Packaging is not a substitute for OAuth** and does not guarantee the ChatGPT web connector will install it.

For current ChatGPT web connectivity, deploy an OAuth 2.1 authorization-code + PKCE integration in front of the MCP endpoint (or implement it in the server) with an identity provider, protected-resource metadata, issuer discovery, resource-bound access tokens, token validation and per-user authorization. Do not publish or deploy an unauthenticated fallback. See [OpenAI authentication guidance](https://developers.openai.com/plugins/build/auth) and [custom MCP setup](https://developers.openai.com/api/docs/guides/custom-mcp-server).

## Pocket ID (recommended identity provider)

Pocket ID can provide interactive user sign-in through OIDC; it does **not** automatically turn the current HS256 fixed-token endpoint into a ChatGPT-compatible OAuth resource server.

Before implementation, verify Pocket ID's **actual** capabilities and metadata at its public issuer URL:

- OIDC discovery (`/.well-known/openid-configuration`), authorization and token endpoints;
- authorization-code + PKCE S256, refresh tokens / `offline_access`;
- whether the ChatGPT callback can be registered as a redirect URI;
- token issuer, `aud`, signature/JWKS and a safe way to identify the user;
- whether client registration is static only; if so, provision the ChatGPT OAuth client explicitly.

The MCP side must additionally expose OAuth protected-resource metadata and a standards-compliant bearer challenge, validate an **access** token scoped to this MCP resource (not merely any Pocket ID login token), and enforce a server-side allowlist mapping user identities to target Secret names. If Pocket ID does not issue resource-audience access tokens suitable for the MCP, use an OAuth authorization-server bridge that exchanges Pocket ID login for its own MCP-specific access tokens.

**Do not** map every successfully authenticated Pocket ID user to the Kubernetes service account's entire Secret read permission. Initially allow only the approved user and the KingP2P test Secret. Keep the existing CLI JWT path working separately during migration, with an explicit authentication mode and regression tests.

Required deployment information (not secrets): the public Pocket ID issuer URL, configured OAuth client ID, redirect URI support, and intended authorized user identities. Store any OAuth client secret only in Kubernetes Sealed Secrets.

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
