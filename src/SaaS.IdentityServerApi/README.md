# SaaS API Key + IdentityServer4 Extension Grant Demo

This project demonstrates a **SaaS-style API key system** integrated with **IdentityServer4** using a **custom extension grant** (`grant_type=api_key`) to exchange long-lived API keys for **short-lived JWT access tokens**.

## Features
- IdentityServer4 (in-memory configuration)
- Custom `api_key` extension grant validator
- API key storage (EF Core InMemory) with:
  - Hash-at-rest (HMAC) — secret never stored
  - Scopes, expiration, revocation, last-used timestamps
  - Tenant & owner user association
- Short-lived (15 min) access tokens with:
  - `sub` = service principal style: `spn:ak_<publicId>`
  - `api_key_id`, `owner_sub`, `tenant_id`, `scope` claims
- Protected resource endpoint requiring `scope=api1`
- Swagger UI (development)
- Minimal “demo user/tenant” via headers (replace with real auth in production)

## Run
```bash
dotnet restore
dotnet run --project src/SaaS.IdentityServerApi/SaaS.IdentityServerApi.csproj
```

App listens (dev):
- https://localhost:5001 (Kestrel dev cert required; run `dotnet dev-certs https --trust` if not trusted)

## Create an API Key
The demo fakes the authenticated *owner user* and *tenant* with headers:
- `X-Demo-User: user-123`
- `X-Demo-Tenant: tenant-abc`

```bash
curl -k -X POST https://localhost:5001/api/apikeys \
  -H "Content-Type: application/json" \
  -H "X-Demo-User: user-123" \
  -H "X-Demo-Tenant: tenant-abc" \
  -d '{"Name":"CI Key","Scopes":"api1","TtlMinutes":1440}'
```

Response (example):
```json
{
  "apiKey": "ak_JKQW72M3.AAAA....",
  "id": "JKQW72M3",
  "tenant": "tenant-abc",
  "name": "CI Key",
  "scopes": ["api1"],
  "expiresUtc": "2025-09-23T20:15:00Z"
}
```
Store `apiKey` securely (shown once).

## Exchange API Key for Access Token
```bash
API_KEY="ak_JKQW72M3.AAAA...."

curl -k -X POST https://localhost:5001/connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=api_key" \
  -d "api_key=$API_KEY" \
  -d "scope=api1"
```

Response:
```json
{
  "access_token":"<JWT>",
  "expires_in":900,
  "token_type":"Bearer",
  "scope":"api1"
}
```

## Call Protected Endpoint
```bash
TOKEN="<access_token_from_previous_step>"
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:5001/api/data
```

Example output:
```json
{
  "message": "Protected SaaS data",
  "subject": "spn:ak_JKQW72M3",
  "tenant": "tenant-abc",
  "owner": "user-123",
  "scopes": ["api1"],
  "issuedVia": "api_key"
}
```

## List API Keys
```bash
curl -k -H "X-Demo-User: user-123" -H "X-Demo-Tenant: tenant-abc" https://localhost:5001/api/apikeys
```

## Revoke API Key
```bash
curl -k -X DELETE https://localhost:5001/api/apikeys/JKQW72M3 \
  -H "X-Demo-User: user-123" \
  -H "X-Demo-Tenant: tenant-abc"
```

## Design Notes
| Concern | Approach |
|---------|----------|
| Secret Storage | Only HMAC hash saved (HMAC(secretServer, publicId:secret)) |
| Key Format | `ak_<PUBLICID>.<base64url(secret)>` |
| Token Lifetime | 900s (15 minutes) configurable via client |
| Claims | `sub`, `api_key_id`, `owner_sub`, `tenant_id`, one `scope` claim per scope |
| Revocation | Set `RevokedUtc`; further exchanges fail |
| Last Used | Updated on successful exchange |

## Production Hardening
- Replace InMemory DB with SQL/Postgres provider
- Real authentication & authorization for key management endpoints
- Rate limiting token exchanges (Redis)
- Observability: log IP, user-agent on exchanges
- Rotate `ApiKeys:HashSecret` (add versioning column)
- Add key usage anomaly detection
- Add UI/portal for managing keys (description, last used, rotate)

## Switching to Duende IdentityServer
If upgrading to .NET 8 or requiring commercial support:
- Update package references to Duende
- Namespace adjustments (IdentityServer4 → Duende.IdentityServer)
- Licensing considerations: https://duendesoftware.com

## Disclaimer
This sample is for instructional purposes. Review and adapt security best practices for your environment.

Happy building!