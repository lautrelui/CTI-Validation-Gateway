# CTI Validation Gateway (CVG)

Secure relay and delivery guarantor for identifier verification between OneBox nodes, the IVS (Identity Verification Service), and the Central DIT.

## Architecture

```
OneBox ──POST──▶ CVG ──POST──▶ IVS (verify identifier)
                  │                    │
                  │◀───claim+sig───────┘
                  │
                  ├── verify signature (HS512 / remote)
                  ├── store result
                  ├──POST──▶ Central DIT (callback with claim)
                  │
                  ◀── return acknowledgment to OneBox (no claim)
```

**Key rules:**
- CVG does **not** return the signed claim to OneBox.
- CVG **posts** the verification result (including the claim) to Central DIT.
- CVG **guarantees delivery** via a persistent retry queue.
- Every request must include a `verification_request_id` (assigned by Central DIT).

## Request Flow

1. Central DIT creates a `verification_request_id` and passes it to OneBox.
2. OneBox sends a verification request to CVG with the `verification_request_id`.
3. CVG calls IVS to verify the identifier.
4. CVG validates the IVS response signature (HS512 locally or via IVS remote endpoint).
5. CVG POSTs the result to Central DIT's callback endpoint.
6. OneBox receives only a submission acknowledgment (`status: "submitted"`).

If Central DIT is unreachable, the callback is queued and retried automatically (up to 10 times with exponential backoff).

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `IVS_MODE` | No | `simulator` | `simulator` or `external` |
| `IVS_BASE_URL` | If external | `http://localhost:3001` | IVS endpoint |
| `IVS_API_KEY` | If external | - | IVS API key |
| `IVS_SIGNING_KEY` | Recommended | - | Shared HS512 signing key (same as IVS `SIGNING_KEY`) |
| `IVS_CLAIM_VERIFY_MODE` | No | `auto` | `local`, `remote`, `auto`, or `none` |
| `CENTRAL_DIT_BASE_URL` | **Yes** (external) | - | Central DIT endpoint |
| `CENTRAL_DIT_API_KEY` | Yes | - | Central DIT API key |
| `CENTRAL_DIT_CALLBACK_PATH` | No | `/api/v1/verification/callbacks/ivs` | Callback path |
| `CENTRAL_DIT_TIMEOUT` | No | `5000` | Callback timeout (ms) |
| `CVG_HMAC_KEY` | Recommended | random | HMAC key for identifier protection |
| `CVG_QUEUE_ENABLED` | No | `true` | Enable/disable retry queue |

## API Endpoints

### Verification (OneBox → CVG)

**POST** `/api/v1/verification/identifiers`

Headers: `X-Api-Key`, `X-OneBox-Id`

```json
{
  "verification_request_id": "vr-20260321-001",
  "identifier": {
    "identifier_type": "NIU",
    "raw_value": "123456789",
    "issuer_country": "CG"
  },
  "request_context": {
    "requesting_assujetti_id": "BGFI",
    "onebox_id": "OBX-BGFI-01",
    "purpose": "kyc_verification"
  }
}
```

**Success response** (callback delivered):
```json
{
  "status": "submitted",
  "verification_request_id": "vr-20260321-001",
  "correlation_id": "cvg-20260321-000001",
  "gateway_audit_ref": "..."
}
```

**Pending response** (callback queued for retry):
```json
{
  "status": "pending_callback_delivery",
  "verification_request_id": "vr-20260321-001",
  "correlation_id": "cvg-20260321-000001",
  "gateway_audit_ref": "..."
}
```

### Status Check

**GET** `/api/v1/verification/requests/:correlation_id`

### Health

**GET** `/api/v1/health`

Returns status of database, IVS, Central DIT, and callback queue.

### Admin

| Endpoint | Description |
|---|---|
| `GET /api/v1/admin/callback-queue` | List callback delivery queue items |
| `GET /api/v1/admin/callback-queue/stats` | Callback queue statistics |
| `POST /api/v1/admin/callback-queue/retry` | Trigger callback retry processing |
| `GET /api/v1/admin/verification-queue` | List IVS retry queue items |
| `GET /api/v1/admin/stats` | Full system statistics |

## Central DIT Callback Payload

CVG POSTs this to Central DIT after successful IVS verification:

```json
{
  "verification_request_id": "vr-20260321-001",
  "correlation_id": "cvg-20260321-000001",
  "gateway_id": "CVG-CTI-01",
  "gateway_audit_ref": "...",
  "onebox_id": "OBX-BGFI-01",
  "requesting_assujetti_id": "BGFI",
  "verification_status": "verified",
  "claim": { "...signed claim from IVS..." },
  "signature_verified": true,
  "signature_method": "local_hs512",
  "delivered_at": "2026-03-21T10:00:00.000Z"
}
```

## Callback Retry Logic

If Central DIT is unreachable, the callback is queued with this retry schedule (in minutes):

`1, 2, 5, 15, 30, 60, 120, 240, 480, 720`

After 10 retries, the callback is marked as `failed`. Operators can monitor via the admin dashboard and trigger manual retries.

## Running

```bash
cp .env.example .env
# Edit .env with your configuration
npm install
npm start
```

Dashboard: `http://localhost:3010/dashboard`
