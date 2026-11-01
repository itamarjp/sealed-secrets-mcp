# ChatGPT + Pocket ID OAuth (staged; no deployment)

ChatGPT is an OAuth MCP client. Pocket ID is the authorization server and passkey identity provider. `sealed-secrets-mcp` is an OAuth-protected resource server, with the public URL `https://seal.ispbrasil.com.br/mcp`.

The repo now supports two **exclusive** server authentication modes:

- `SEAL_AUTH_MODE=jwt` (default): existing short-lived server-minted HS256 bearer tokens, for CLI clients.
- `SEAL_AUTH_MODE=pocketid`: validate Pocket ID's RS256 JWT **access tokens** using its JWKS, requiring an exact issuer, resource audience, scope `seal:existing`, expiry, and exact user `sub`.

The Pocket ID mode exposes only `seal_existing_secret`. `generate_sealed_secret` is intentionally unavailable to ChatGPT. The cluster Role must independently restrict reads to the single approved Secret. No credential is embedded in the package.

## One-time Pocket ID administration

**Do not create an OIDC client manually yet** if using CIMD. Pocket ID supports Client ID Metadata Documents (CIMD), which ChatGPT can use instead of a manually registered client, provided the instance supports this feature.

1. Verify Pocket ID is recent enough for OAuth authorization-server discovery, API resources and CIMD support. Inspect `https://id.ispbrasil.com.br/.well-known/oauth-authorization-server` and its `client_id_metadata_document_supported` capability. Do not assume this is enabled on the running instance.
2. Pocket ID → **Administration → APIs → Add API**:
   - Name: `Sealed Secrets MCP`
   - Resource: `https://seal.ispbrasil.com.br/mcp` (exact match to `SEAL_AUDIENCE`)
   - Permission: `seal:existing` (user-delegated).
3. Pocket ID → **Application Configuration → OIDC**: allowlist the **exact** ChatGPT CIMD URL advertised by the ChatGPT connection setup. The stable form is `https://chatgpt.com/oauth/client.json` when supported; ChatGPT may instead use a callback-specific metadata URL. Do not allow wildcard clients.
4. Pocket ID → API access for **Metadata document clients**: allow only `seal:existing`. This setting covers every accepted CIMD client; keep the CIMD URL allowlist restricted.
5. In the newly created OIDC client Access settings, restrict **Allowed User Groups** to a group containing only your account. Do not select All Users.
6. Identify your **exact Pocket ID user subject (`sub`)** from the admin interface or a trusted local token inspection. Configure it as `SEAL_POCKET_ID_SUB`; never substitute email, username, or a guess.
7. Confirm the API's resource-bound access tokens have `aud=https://seal.ispbrasil.com.br/mcp` and scope `seal:existing`. Do not use ID tokens.

## MCP server settings for the Kubernetes deployment

```yaml
env:
  - name: SEAL_AUTH_MODE
    value: pocketid
  - name: SEAL_AUDIENCE
    value: https://seal.ispbrasil.com.br/mcp
  - name: SEAL_POCKET_ID_ISSUER
    value: https://id.ispbrasil.com.br
  - name: SEAL_POCKET_ID_SUB
    value: "REPLACE_WITH_EXACT_POCKET_ID_SUB"
```

The OAuth mode does not require `SEAL_SIGNING_KEY_FILE`. Do not deploy until the real sub is configured through reviewed GitOps configuration. Do not commit access tokens, R2 credentials, or the contents of any Kubernetes Secret.

## ChatGPT connection

The portable `plugin.json` and `mcp.json` declare the MCP server and Pocket ID OAuth authorization through CIMD. In ChatGPT → Plugins → Add custom MCP server, use the HTTPS URL above and OAuth authentication; inspect the offered callback/CIMD URL and configure the exact URL in Pocket ID. ChatGPT must request scope `seal:existing` and resource `https://seal.ispbrasil.com.br/mcp`.

The MCP server advertises RFC 9728 protected-resource metadata at:

- `https://seal.ispbrasil.com.br/.well-known/oauth-protected-resource/mcp`
- `https://seal.ispbrasil.com.br/.well-known/oauth-protected-resource`

The ingress must route those paths to the service. Verify the unauthorized MCP response includes a standards-compliant Bearer challenge and links to the resource metadata during end-to-end testing.

## KingP2P security checks

1. Kubernetes RBAC: read-only `get` with `resourceNames: [kingp2p-r2-pgbackrest]` in namespace `kingp2p-test`, and no broader Secret permission.
2. Invalid signature, wrong issuer/audience, missing scope, wrong user `sub`, expired token and ID tokens are all rejected.
3. Only `seal_existing_secret` appears in the authenticated ChatGPT tool listing.
4. Tool call `{"namespace":"kingp2p-test","name":"kingp2p-r2-pgbackrest"}` returns only strict-scope ciphertext.
5. Never commit plaintext or permit auto-deploy. Review the returned SealedSecret before adding it to the GitOps PR.
6. Test an unauthorized account to ensure it cannot authorize the client or call the resource server.

## Existing CLI clients

The default `jwt` mode and `token` subcommand remain for CLI integrations. Never paste the resulting bearer token into conversations. The ChatGPT OAuth mode and JWT mode should not be combined on a single endpoint.

## References

- [Pocket ID: APIs and permissions](https://pocket-id.org/docs/guides/apis)
- [Pocket ID: Client ID Metadata Documents](https://pocket-id.org/docs/guides/client-id-metadata-documents)
- [OpenAI: Plugin OAuth](https://developers.openai.com/plugins/build/auth)
- [OpenAI: Connecting custom MCP servers](https://developers.openai.com/api/docs/guides/custom-mcp-server)
