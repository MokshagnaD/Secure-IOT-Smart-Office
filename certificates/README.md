# certificates/

This directory holds the self-signed TLS certificate and private key used
for local development.

## Files

| File         | Purpose                                      |
|--------------|----------------------------------------------|
| `server.crt` | Self-signed X.509 certificate (public)       |
| `server.key` | ECC private key — **never commit this file** |

## How the certificate was generated

```bash
openssl req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:P-256 \
  -keyout server.key \
  -out server.crt \
  -days 365 \
  -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
```

- Curve   : P-256 (SECP256R1) — NIST-approved, 128-bit security level
- Validity: 365 days (local dev only)
- SAN     : covers both `localhost` and `127.0.0.1`

## Two-layer security model

```
Application layer : AES-256-GCM  (encrypts sensor payload)
Transport layer   : TLS 1.3      (encrypts the entire TCP connection)
```

TLS 1.3 protects the connection itself (prevents eavesdropping on the
channel). AES-256-GCM provides an additional application-level encryption
layer so that even if TLS were somehow stripped, the payload remains
encrypted.

## Why we do NOT disable certificate verification

The client loads `server.crt` as a trusted CA and verifies the server
certificate. This prevents man-in-the-middle attacks. Disabling
verification (`check_hostname=False`, `verify_mode=CERT_NONE`) would make
TLS useless for authentication.

## Production note

In production, replace these files with certificates issued by a trusted
Certificate Authority (CA) or an internal PKI.
