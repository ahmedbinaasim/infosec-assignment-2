# SecureChat: PKI-Enabled Secure Chat System

**Course:** Information Security (CS-3002, Fall 2025)
**Assignment:** Assignment #2
**Institution:** FAST-NUCES (National University of Computer and Emerging Sciences)

---

## 🎯 Overview

**SecureChat** is a console-based, PKI-enabled secure chat system demonstrating **CIANR** security properties:

- **C**onfidentiality - AES-128 encryption
- **I**ntegrity - SHA-256 hashing with RSA signatures
- **A**uthenticity - X.509 PKI certificates
- **N**on-Repudiation - Signed session receipts
- F**R**eshness - Sequence numbers and timestamps

This project implements cryptographic protocols **at the application layer** (no TLS/SSL) over plain TCP sockets, demonstrating how real-world security systems combine primitives to achieve comprehensive protection.

### ✨ Key Features

✅ Self-built Certificate Authority (CA)
✅ X.509 certificate validation
✅ Diffie-Hellman key exchange
✅ AES-128 encryption with PKCS#7 padding
✅ Per-message RSA-SHA256 signatures
✅ Replay attack protection (sequence numbers)
✅ Append-only transcript logging
✅ Signed SessionReceipts for non-repudiation
✅ Offline third-party verification
✅ MySQL user authentication with salted SHA-256

---

## 📋 Table of Contents

- [Architecture](#-architecture)
- [Installation](#%EF%B8%8F-installation)
- [Quick Start](#-quick-start)
- [Module Documentation](#-module-documentation)
- [Testing](#-testing)
- [Project Structure](#%EF%B8%8F-project-structure)
- [Implementation Status](#-implementation-status)
- [Assignment Submission](#-assignment-submission)
- [References](#-references)

---

## 🏗 Architecture

### Protocol Flow Diagram

```
┌─────────────┐                                    ┌─────────────┐
│   Client    │                                    │   Server    │
│   (Alice)   │                                    │    (Bob)    │
└──────┬──────┘                                    └──────┬──────┘
       │                                                  │
       │  1. HELLO (client_cert, nonce)                  │
       │─────────────────────────────────────────────────>│
       │                                                  │
       │  2. SERVER_HELLO (server_cert, nonce)           │
       │<─────────────────────────────────────────────────│
       │         [Both validate certificates]             │
       │                                                  │
       │  3. DH_CLIENT (p, g, A)                         │
       │─────────────────────────────────────────────────>│
       │                                                  │
       │  4. DH_SERVER (B)                               │
       │<─────────────────────────────────────────────────│
       │   [Both derive session key K from DH]           │
       │                                                  │
       │  5. REGISTER/LOGIN (encrypted credentials)      │
       │─────────────────────────────────────────────────>│
       │                                                  │
       │  6. AUTH_RESPONSE (success/error)               │
       │<─────────────────────────────────────────────────│
       │                                                  │
       │  7. MSG (seqno, ts, ct, sig)                    │
       │─────────────────────────────────────────────────>│
       │      [Encrypted with K, signed with RSA]         │
       │      [Logged to append-only transcript]          │
       │                                                  │
       │  8. MSG (seqno, ts, ct, sig)                    │
       │<─────────────────────────────────────────────────│
       │                                                  │
       │         [Session continues...]                   │
       │                                                  │
       │  9. Generate SessionReceipt                     │
       │     Sign(SHA256(transcript))                    │
       │                                                  │
       └──────────────────────────────────────────────────┘
```

### Security Layers

1. **Control Plane** - PKI handshake and authentication
2. **Key Agreement** - Diffie-Hellman session key establishment
3. **Data Plane** - Encrypted message exchange with signatures
4. **Teardown** - Non-repudiation via signed session receipts

---

## 🗂️ Project Structure

```
infosec-assignment-2/
├── app/
│   ├── crypto/
│   │   ├── aes.py              # ✅ AES-128-ECB encryption + PKCS#7
│   │   ├── dh.py               # ✅ Diffie-Hellman key exchange (RFC 3526)
│   │   ├── pki.py              # ✅ X.509 certificate validation
│   │   └── sign.py             # ✅ RSA-SHA256 signatures
│   ├── storage/
│   │   ├── db.py               # ✅ MySQL user authentication
│   │   └── transcript.py       # ✅ Transcript logging & receipts
│   ├── common/
│   │   ├── protocol.py         # ✅ Pydantic message models
│   │   └── utils.py            # ✅ Helper functions
│   ├── client.py               # ✅ Client implementation
│   └── server.py               # ✅ Server implementation
├── scripts/
│   ├── gen_ca.py               # 🔄 Generate Root CA
│   ├── gen_cert.py             # 🔄 Issue certificates
│   └── verify_receipt.py       # 🔄 Offline receipt verification
├── tests/
│   ├── test_section_2.3.py     # ✅ Session key establishment test
│   ├── test_section_2.4.py     # ✅ Encrypted chat test
│   ├── test_section_2.5.py     # ✅ Non-repudiation test
│   ├── test_full_protocol.py   # 🔄 End-to-end integration
│   └── test_attacks.py         # 🔄 Security attack demonstrations
├── certs/                      # Generated certificates (gitignored)
├── transcripts/                # Session transcripts (gitignored)
├── evidence/                   # Test outputs for submission
├── .env.example                # Configuration template
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── CLAUDE.md                   # Project guidelines
├── TESTING_GUIDE_2.3.md        # ✅ Section 2.3 testing guide
├── TESTING_GUIDE_2.4.md        # ✅ Section 2.4 testing guide
└── TESTING_GUIDE_2.5.md        # ✅ Section 2.5 testing guide

Legend: ✅ Implemented | 🔄 In Progress | ⏳ Planned
```

---

## ⚙️ Installation

### Prerequisites

- **Python 3.8+**
- **MySQL 8.0+** (for user authentication)
- **Virtual environment** (recommended)

### Step 1: Clone Repository

```bash
git clone <your-fork-url>
cd infosec-assignment-2
```

### Step 2: Create Virtual Environment

```bash
# Linux/Mac
python3 -m venv .venv
source .venv/bin/activate

# Windows
python -m venv .venv
.venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**Dependencies:**
- `cryptography` - Crypto primitives (AES, RSA, X.509, DH)
- `pydantic` - Message validation and serialization
- `PyMySQL` - MySQL database connectivity
- `python-dotenv` - Environment configuration

### Step 4: Setup MySQL Database

```bash
# Start MySQL (via Docker - recommended)
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8
```

### Step 5: Configure Environment

```bash
# Copy example configuration
cp .env.example .env

# Edit .env with your settings
nano .env
```

### Step 6: Generate Certificates

```bash
# Generate Root CA (coming in next commit)
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Generate certificates (coming in next commit)
python scripts/gen_cert.py --cn server.local --out certs/server
python scripts/gen_cert.py --cn client.local --out certs/client
```

---

## 🚀 Quick Start

### Run Module Tests

```bash
# Test Section 2.3: Session Key Establishment
python tests/test_section_2.3.py

# Test Section 2.4: Encrypted Chat
python tests/test_section_2.4.py

# Test Section 2.5: Non-Repudiation
python tests/test_section_2.5.py
```

### Expected Output

Each test should display:
- ✅ All security properties verified
- ✅ Encryption/decryption working
- ✅ Signatures valid
- ✅ Replay attacks blocked
- ✅ Tampering detected
- ✅ Final summary: "ALL TESTS PASSED"

---

## 📚 Module Documentation

### Module 2.3: Session Key Establishment (DH)

**Files:** `app/client.py`, `app/server.py`, `app/crypto/dh.py`

**Features:**
- Classical Diffie-Hellman key exchange
- RFC 3526 Group 14 (2048-bit MODP)
- Session key derivation: `K = Trunc16(SHA256(Ks))`

**Testing:** `python tests/test_section_2.3.py`
**Documentation:** `TESTING_GUIDE_2.3.md`

### Module 2.4: Encrypted Chat and Message Integrity

**Files:** `app/client.py`, `app/server.py`

**Features:**
- AES-128-ECB encryption with PKCS#7 padding
- Per-message RSA-SHA256 signatures
- Strict sequence number enforcement
- Replay protection

**Testing:** `python tests/test_section_2.4.py`
**Documentation:** `TESTING_GUIDE_2.4.md`

### Module 2.5: Non-Repudiation and Session Closure

**Files:** `app/storage/transcript.py`

**Features:**
- Append-only transcript logging
- TranscriptHash computation
- Signed SessionReceipt generation
- Offline third-party verification

**Testing:** `python tests/test_section_2.5.py`
**Documentation:** `TESTING_GUIDE_2.5.md`

---

## 🧪 Testing

### Run All Tests

```bash
# Individual module tests
python tests/test_section_2.3.py
python tests/test_section_2.4.py
python tests/test_section_2.5.py
```

### Evidence Collection

```bash
# Capture test output
python tests/test_section_2.5.py > evidence/section_2.5_output.txt 2>&1

# Inspect certificates (after generation)
openssl x509 -in certs/ca_cert.pem -text -noout > evidence/ca_cert_inspection.txt
```

---

## ✅ Implementation Status

### Completed Modules

- ✅ **Module 2.3:** Session Key Establishment (DH)
- ✅ **Module 2.4:** Encrypted Chat and Message Integrity
- ✅ **Module 2.5:** Non-Repudiation and Session Closure

### In Progress

- 🔄 Certificate generation scripts (gen_ca.py, gen_cert.py)
- 🔄 Full client-server integration
- 🔄 Offline receipt verification tool

### Planned

- ⏳ Attack demonstrations (replay, tampering, MitM)
- ⏳ Wireshark evidence collection
- ⏳ Complete end-to-end integration test

---

## 📦 Assignment Submission

### Required Files

- [ ] GitHub repository link (in README)
- [ ] Downloaded ZIP of repository
- [ ] MySQL schema dump
- [ ] Report document (`.docx`)
- [ ] Test report document (`.docx`)
- [ ] Wireshark captures (`.pcapng`)
- [ ] Certificate inspection outputs

### Testing Evidence Checklist

- [ ] Certificate validation (valid and invalid)
- [ ] Encrypted traffic in Wireshark (no plaintext)
- [ ] Replay attack blocked
- [ ] Tampering detected (SIG_FAIL)
- [ ] Invalid certificate rejected (BAD_CERT)
- [ ] SessionReceipt generation
- [ ] Offline verification demonstration

---

## 📖 References

### Assignment Specification

- **PDF:** `IS_Assignment_2.pdf`
- **Implemented Sections:**
  - Section 1.1-1.4: Protocol phases (Pages 3-5)
  - Section 2.1-2.5: Implementation requirements (Pages 6-9)

### Cryptographic Standards

- **RFC 3526:** Diffie-Hellman Group 14
- **PKCS#7:** Padding scheme
- **PKCS#1 v1.5:** RSA signature padding
- **X.509:** PKI certificates
- **FIPS 180-4:** SHA-256 specification

---

## ⚠️ Important Notes

### What This Implementation DOES

✅ Demonstrates CIANR security properties
✅ Encrypts all message content
✅ Validates certificates
✅ Detects replay attacks
✅ Detects message tampering
✅ Provides non-repudiation

### What This Implementation DOES NOT

❌ Use TLS/SSL (deliberately - application layer only)
❌ Implement perfect forward secrecy
❌ Provide DoS protection
❌ Handle all edge cases (educational code)

**⚠️ Warning:** This is educational code for assignment purposes. Do NOT use in production.

---

## 🎓 Academic Integrity

This repository demonstrates a complete implementation of the SecureChat assignment. All code follows the assignment specification exactly.

**For Students:** Use this as a reference for understanding the protocol, but implement your own code. Direct copying violates academic integrity policies.

---

## 📞 Contact

For questions or issues:
- Refer to `CLAUDE.md` for development guidelines
- Check `TESTING_GUIDE_*.md` for module-specific instructions
- Review assignment PDF for specification details

---

**Last Updated:** November 2025
**Implementation Status:** Modules 2.3-2.5 Complete ✅

---

## 💡 Quick Command Reference

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Testing
python tests/test_section_2.3.py  # DH key exchange
python tests/test_section_2.4.py  # Encrypted chat
python tests/test_section_2.5.py  # Non-repudiation

# Database (Docker)
docker run -d --name securechat-db -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass -p 3306:3306 mysql:8

# Evidence Collection
python tests/test_section_2.5.py > evidence/output.txt 2>&1
```

---

**End of README**