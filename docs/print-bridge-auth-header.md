# Print Bridge Auth Header Update

## Audience
- Frontend engineers integrating with the TABL Print Bridge
- QA validating bridge ⇄ app communication

## Effective Date
- Applies immediately to environments running the `X-Authorization` header release (see deployment notes from backend team).

## Summary
- For **calls made to the Print Bridge service only**, send JWT credentials in the custom header `X-Authorization: Bearer <token>`.
- The backend still accepts the standard `Authorization` header for backward compatibility, but the frontend should switch to `X-Authorization` for the Print Bridge request path so we can decouple it from browser-managed auth.

## Scope
- ✅ Applies: Any request your client makes directly to the bridge (`/assign`, `/print`, or other authenticated bridge endpoints).
- ❌ Does **not** affect: Requests to other backend services, POS APIs, or browser-native fetch calls unrelated to the Print Bridge.

## Header Specification
| Header Name        | Required | Format                         | Notes                                                                 |
|--------------------|----------|--------------------------------|-----------------------------------------------------------------------|
| `X-Authorization`  | Yes      | `Bearer <JWT>`                 | Must include the `Bearer` prefix followed by the encoded JWT token.   |
| `Content-Type`     | Yes      | `application/json`             | For JSON request bodies (e.g., `/assign`, `/print`, `/print/global`). |

### Example
```http
POST https://<bridge-host>/assign
X-Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "terminalId": "t1",
  "ip": "192.168.1.50"
}

POST https://<bridge-host>/print/global
X-Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "printerId": "kitchen",
  "data": "<base64-escpos>"
}
```

## Frontend Work Required
1. Locate the code path that issues requests to the Print Bridge (typically the “Assign printer” / “Send print job” flows).
2. Replace existing `Authorization` headers with `X-Authorization`.
3. Confirm no other API calls are modified—this change is isolated to the Print Bridge integration.
4. Smoke test bridge interactions to verify assignments and print jobs still succeed.

## Backend Notes
- The bridge now normalizes both `Authorization` and `X-Authorization`. Tokens are validated the same way regardless of header.
- `/printers` and `/ui` continue to be unauthenticated; no header change needed there.

## Testing Expectations
- QA should validate at least one assignment and one print job using the updated header.
- Automated integration tests remain unchanged; manual verification is sufficient once the frontend patch is deployed.

## Questions
Ping the backend team in `#tabl-device-bridge` with deployment status or troubleshooting questions.
