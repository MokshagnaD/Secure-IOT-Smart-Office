# Secure IoT-Based Smart Office System with Role-Based Access Control (RBAC) and Cryptography

## Project Overview

A zero-trust simulated **Smart Office IoT system** demonstrating enterprise-grade cryptographic security and **Role-Based Access Control (RBAC)**. 

The system simulates enterprise IoT access points and environmental monitors:
- **`door_server_room`**: Restricted High-Security Server Room Door Lock.
- **`door_main_entrance`**: General Office Entrance Access Lock.
- **`hvac_office`**: Office Climate & Temperature Controller.
- **`motion_meeting_room`**: Meeting Room Occupancy Sensor.

All devices and client badges communicate with the central IoT Security Gateway over an encrypted, authenticated, replay-protected channel with multi-tier RBAC authorization — entirely in Python with no hardware required.

---

## Motivation: Why Smart Office Over Smart Home?

In real-world deployment, smart homes present practical challenges for enterprise cryptographic and access control models:
1. **Lack of User Hierarchy in Homes**: Consumer smart homes rarely feature strict cryptographic access tiers. Family members do not manage asymmetric cryptographic keys or restricted zero-trust boundaries.
2. **Enterprise Smart Office Standards**: Corporate office environments **require** strict access boundaries:
   - **IT Administrators** must manage network servers, configure climate controls, audit security logs, and provision cryptographic device credentials.
   - **Regular Employees** must have seamless badge-in access to general office floors and meeting rooms, but are strictly **forbidden** from entering server rooms or altering building infrastructure.
3. **Compliance & Zero Trust**: Real-world enterprise smart offices are governed by compliance frameworks (ISO 27001, SOC 2, NIST SP 800-53) requiring cryptographic audit trails, hardware non-repudiation, and explicit authorization policies.

---

## Core Security Architecture

The system implements a **three-layer security model**:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      ENTERPRISE SMART OFFICE                           │
│                                                                        │
│   Server Room Door     Main Entrance Door     HVAC Climate Controller  │
│  (door_server_room)  (door_main_entrance)         (hvac_office)        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   THREE-LAYER SECURITY MODEL                           │
│                                                                        │
│  1. Transport Layer     : TLS 1.3 encrypted TCP connection            │
│  2. Application Layer   : AES-256-GCM authenticated payload encryption │
│                           + ECDSA digital signature (P-256 / SHA-256) │
│                           + Ephemeral ECDH key agreement (HKDF-SHA256) │
│  3. Authorization Layer : Role-Based Access Control (RBAC)             │
│                           Policy Enforcement Point (PEP / PDP)         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       IoT SECURITY GATEWAY                             │
│                                                                        │
│  • Step 1: TLS 1.3 Handshake                                           │
│  • Step 2: Hardware Device Whitelist & Registry Authentication         │
│  • Step 3: ECDH Session Key Derivation                                 │
│  • Step 4: Digital Signature Verification (Trusted Disk Public Key)    │
│  • Step 5: AES-256-GCM Decryption                                      │
│  • Step 6: Replay Protection (Window + UUID Deduplication)            │
│  • Step 7: RBAC Policy Engine (Role vs. Resource Action)               │
│                                                                        │
│        [RBAC GRANTED]                         [RBAC DENIED]            │
│  (e.g., Alice unlocks Server Room)    (e.g., Bob blocked from Server   │
│                                              Room - 403 Forbidden)     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Role-Based Access Control (RBAC) Model

### Corporate Identities

| Identity | Name | Assigned Role | Department | Badge ID |
|---|---|---|---|---|
| `admin_alice` | **Alice Chen** | `ADMINISTRATOR` | Infrastructure & Security | `BADGE-ADM-001` |
| `employee_bob` | **Bob Martinez** | `EMPLOYEE` | Software Engineering | `BADGE-EMP-104` |
| `guest_charlie` | **Charlie Visitor** | `GUEST` | Contractor / Visitor | `BADGE-GST-999` |

### Permissions Matrix

| Resource / Action | 👑 Administrator (`admin_alice`) | 👤 Employee (`employee_bob`) | 🏷️ Guest (`guest_charlie`) | Policy Enforcement |
|---|:---:|:---:|:---:|---|
| **Unlock Main Office Entrance** | ✅ ALLOWED | ✅ ALLOWED | ❌ DENIED | Standard office entry |
| **Unlock Server Room Door** | ✅ **ALLOWED** | ❌ **DENIED (403)** | ❌ **DENIED (403)** | **Restricted Infrastructure Zone** |
| **Read Office Climate / Telemetry** | ✅ ALLOWED | ✅ ALLOWED | ❌ DENIED | Telemetry read |
| **Configure HVAC Setpoints** | ✅ **ALLOWED** | ❌ **DENIED (403)** | ❌ **DENIED (403)** | Facilities Admin only |
| **Poll Meeting Room Occupancy** | ✅ ALLOWED | ✅ ALLOWED | ✅ ALLOWED | General presence sensor |
| **View Audit Logs & Manage Keys** | ✅ **ALLOWED** | ❌ **DENIED (403)** | ❌ **DENIED (403)** | Security governance |

---

## Cryptographic Specifications

| Component | Primitive / Standard | Description |
|---|---|---|
| **Payload Confidentiality** | `AES-256-GCM` | Authenticated symmetric encryption (256-bit key). Unique 12-byte random nonce per message. |
| **Message Integrity** | `GCM Tag (16 bytes)` | Detects any ciphertext alteration or tampering in transit. |
| **Device Authentication** | `ECDSA (SECP256R1 + SHA-256)` | Cryptographic non-repudiation. Signed with device's registered private key; verified with server's trusted registry. |
| **Key Exchange** | `ECDH + HKDF-SHA256` | Ephemeral Elliptic Curve Diffie-Hellman key agreement wraps session keys securely. |
| **Transport Security** | `TLS 1.3 / TLS 1.2` | Encrypts underlying TCP socket; verifies server identity certificate. |
| **Replay Protection** | `Timestamp Window + UUID` | 30-second timestamp freshness window combined with in-memory UUID deduplication. |
| **Access Authorization** | `RBAC Engine (PDP/PEP)` | Server evaluates role claims against resource clearance before executing actions. |

---

## Project Structure

```
Secure-IoT-Smart-Home/
├── certificates/              # Auto-generated TLS server certificate & key (dev)
├── client/                    # Simulated IoT devices and smart badges
│   ├── __init__.py
│   └── iot_client.py          # Multi-device client supporting telemetry and RBAC
├── crypto/                    # Cryptographic, protocol, DB & authorization core
│   ├── __init__.py
│   ├── db.py                  # MongoDB Atlas + offline local cache & live state
│   ├── device_registry.py     # Trusted hardware registry of authorized device keys
│   ├── encryption.py          # AES-256-GCM encryption & decryption
│   ├── key_management.py      # ECDH key agreement and HKDF wrapping
│   ├── protocol.py            # Shared TLS framing & multi-layer handshake helpers
│   ├── rbac.py                # RBAC definitions, users, roles, and PDP engine
│   ├── server_identity.py     # Persistent server keypair management
│   ├── signatures.py          # ECDSA signature generation and verification
│   └── tls_setup.py           # Auto-provisions local ECDSA P-256 TLS certificate
├── dashboard/                 # Interactive web dashboard
│   └── index.html             # Zero-trust dark cyber UI with live state & logs
├── dashboard.py               # Combined TLS IoT Server + Web REST API (port 8080)
├── demo.py                    # 6-scenario automated test & demonstration runner
├── device_keys/               # Auto-generated ECC keys for each registered unit
├── logs/                      # Server and client activity logs
├── .env.example               # Optional MongoDB configuration template
├── requirements.txt           # Python dependencies (cryptography, pytest, pymongo)
├── server/                    # Core IoT Security Server
│   ├── __init__.py
│   └── server.py              # Server with TLS, crypto verification & RBAC PEP
└── tests/                     # Automated pytest verification suite
    ├── __init__.py
    ├── test_authentication.py # Device whitelist and registry key persistence
    ├── test_encryption.py     # AES-256-GCM roundtrip & nonce uniqueness
    ├── test_integration.py    # Live TLS socket integration tests
    ├── test_rbac.py           # RBAC unit tests, privilege escalation checks
    └── test_security.py       # Tampering, replay, and bad signature tests
```

---

## Quickstart & Execution

### 1. Install Dependencies

```bash
# Create and activate a virtual environment (recommended)
python -m venv .venv
# Windows: .venv\Scripts\activate  |  macOS/Linux: source .venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

*(Optional)* Copy `.env.example` to `.env` and set `MONGO_URI` to connect MongoDB Atlas. If omitted, the system runs out-of-the-box with its built-in local cache. TLS certificates and device ECC keys are auto-generated on first run.

### 2. Run the Interactive Web Dashboard

Launch both the IoT Gateway and the Web UI:

```bash
python dashboard.py
```

Then open your browser to **`http://localhost:8080`**:
- **Sign In**: Use Administrator (`admin@smartoffice.io` / `Admin@1234`) or register/sign in on the **Employee Login** tab.
- **Start the IoT Server** using the green **▶ Start** button.
- **Test RBAC on Server Room**:
  - As **Admin** $\rightarrow$ Click **"🔑 Badge In"** on Server Room $\rightarrow$ **Access Granted**!
  - As **Employee** $\rightarrow$ Click **"🔑 Badge In"** on Server Room $\rightarrow$ **Access Denied (403 Forbidden)** with instant visual alert and live server terminal log!
- **Test Attack Scenarios**: Run individual or all 4 simulated attacks (Rogue Device, Tampered Cipher, Replay Attack, Forged Signature).

---

### 3. Run the Automated 6-Scenario Demo

To run a headless terminal demonstration of all security scenarios:

```bash
python demo.py
```

**Demonstration Scenarios:**
1. **Smart Office Telemetry**: HVAC, meeting room motion, and entrance door transmit encrypted/signed status.
2. **Employee Access Control**: Bob Martinez unlocks the Main Office Entrance $\rightarrow$ **RBAC GRANTED**.
3. **Privilege Escalation Defense**: Bob Martinez attempts to unlock the Server Room $\rightarrow$ **RBAC DENIED (403)**.
4. **Administrator Operations**: Alice Chen unlocks Server Room and configures HVAC setpoint $\rightarrow$ **RBAC GRANTED**.
5. **Rogue Hardware Rejection**: Unregistered device ID is rejected at the TLS handshake layer.
6. **Cryptographic Defenses**: Injected bit-flip tampering and captured replay attacks are rejected by AES-GCM and deduplication.

---

### 4. Run the Automated Test Suite

```bash
python -m pytest tests/ -v
```

All 44 unit, security, and live TLS integration tests execute and pass.

---

## Defense Mechanisms Summary

| Attack Vector | Attacker Action | System Defense | Outcome |
|---|---|---|---|
| **Eavesdropping** | Sniffing network packets | TLS 1.3 + AES-256-GCM encryption | Attacker sees only opaque encrypted ciphertext. |
| **Ciphertext Tampering** | Bit-flip in encrypted payload | AES-256-GCM 16-byte authentication tag | Decryption raises `InvalidTag`; message dropped. |
| **Signature Forgery** | Signing with unregistered key | Trusted server-side ECC public key registry | ECDSA verification fails; message rejected. |
| **Rogue Device Injection** | Connecting with forged device ID | Strict hardware whitelist & registry check | Connection terminated with `REJECTED`. |
| **Replay Attack** | Replaying a valid captured unlock command | 30-second timestamp window + UUID cache | Duplicate message ID detected; rejected immediately. |
| **Privilege Escalation** | Employee attempting to access restricted Server Room | Policy Enforcement Point (PEP) | Access blocked with `RBAC_PERMISSION_DENIED (403)`. |
| **Role Spoofing** | Employee claiming `ADMIN` role in payload | Identity-bound role verification in PDP | Escalation detected; rejected with `ROLE_SPOOFING_DETECTED`. |
