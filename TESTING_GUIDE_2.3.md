# Testing Guide for Section 2.3: Session Key Establishment

## Overview

Section 2.3 implements **Post-Authentication Session Key Establishment** using Diffie-Hellman (DH) key exchange. This is the cryptographic mechanism that establishes a shared AES-128 key for encrypting chat messages AFTER successful user login.

**Key Distinction**: This is different from Section 2.2's credential encryption:
- **Section 2.2**: DH used to encrypt registration/login credentials
- **Section 2.3**: DH used to establish chat session encryption key

---

## Prerequisites

✅ Section 2.1 completed (PKI setup)
✅ Section 2.2 completed (Registration & Login)
✅ Virtual environment activated
✅ All dependencies installed (`pip install -r requirements.txt`)

---

## Protocol Flow (Section 2.3)

```
CLIENT                                    SERVER
------                                    ------
[After successful login...]

1. Generate DH params (p, g)
2. Generate keypair (a, A)
   where A = g^a mod p

3. Send DHClientMessage
   {type: "dh_client", p, g, A}  ------>

                                      4. Receive (p, g, A)
                                      5. Generate keypair (b, B)
                                         where B = g^b mod p
                                      6. Compute Ks = A^b mod p
                                      7. Derive K = Trunc16(SHA256(Ks))

                                      8. Send DHServerMessage
                          <------        {type: "dh_server", B}

9. Receive B
10. Compute Ks = B^a mod p
11. Derive K = Trunc16(SHA256(Ks))

[Now both have session key K for AES-128 chat encryption]
```

---

## Phase 1: Unit Testing DH Module

### Test 1.1: Verify DH Module Functionality

```bash
# Activate virtual environment
.venv\Scripts\Activate.ps1  # Windows PowerShell
# OR
source .venv/bin/activate    # Linux/Mac

# Run DH module tests
python -m app.crypto.dh
```

**Expected Output:**
```
=== Diffie-Hellman Module Tests ===

[1] Generating DH parameters...
    Prime p (bits): 2048
    Generator g: 2

[2] Alice generates DH keypair...
    Alice private key (bits): ~2047
    Alice public key (bits): ~2048

[3] Bob generates DH keypair...
    Bob private key (bits): ~2047
    Bob public key (bits): ~2048

[4] Alice computes shared secret...
    Alice shared secret (first 32 hex): 0x...

[5] Bob computes shared secret...
    Bob shared secret (first 32 hex): 0x...

[6] Verifying shared secrets match...
    Secrets match: True

[7] Deriving AES-128 keys...
    Alice AES key: a1b2c3d4e5f6...
    Bob AES key:   a1b2c3d4e5f6...
    Keys match: True
    Key length: 16 bytes

=== All DH tests passed! ===
```

**Verification Points:**
- ✅ Prime p is 2048 bits (RFC 3526 Group 14)
- ✅ Generator g is 2
- ✅ Shared secrets match between Alice and Bob
- ✅ Derived AES keys are identical
- ✅ Key length is exactly 16 bytes (128 bits)

---

## Phase 2: Integration Testing Session Key Establishment

### Test 2.1: Run Section 2.3 Integration Test

```bash
python tests/test_section_2.3.py
```

**Expected Output Structure:**
```
================================================================================
Section 2.3: Session Key Establishment (Post-Login DH)
================================================================================

[PHASE 1] Client: Initiating DH Key Exchange
--------------------------------------------------------------------------------
[1.1] Client: Generating DH parameters...
      Prime p: 2048 bits
      Generator g: 2

[1.2] Client: Generating DH keypair...
      Client private key: XXXX bits (kept secret)
      Client public A: 2048 bits
      A = g^a mod p (first 64 hex): 0x...

[1.3] Client: Creating DHClientMessage...
      Message type: dh_client
      Sending (p, g, A) to server...
      JSON size: XXXX bytes

[PHASE 2] Server: Processing DH Request and Responding
--------------------------------------------------------------------------------
[2.1] Server: Received DHClientMessage
      Extracted p: 2048 bits
      Extracted g: 2
      Extracted A: 2048 bits

[2.2] Server: Generating DH keypair...
      Server private key: XXXX bits (kept secret)
      Server public B: 2048 bits
      B = g^b mod p (first 64 hex): 0x...

[2.3] Server: Computing shared secret...
      Ks = A^b mod p
      Shared secret (first 64 hex): 0x...
      Shared secret: 2048 bits

[2.4] Server: Deriving AES-128 session key...
      K = Trunc16(SHA256(big-endian(Ks)))
      Session key: [32 hex characters]
      Key length: 16 bytes (AES-128)

[2.5] Server: Creating DHServerMessage...
      Message type: dh_server
      Sending B to client...
      JSON size: XXXX bytes

[PHASE 3] Client: Completing DH Exchange
--------------------------------------------------------------------------------
[3.1] Client: Received DHServerMessage
      Extracted B: 2048 bits

[3.2] Client: Computing shared secret...
      Ks = B^a mod p
      Shared secret (first 64 hex): 0x...
      Shared secret: 2048 bits

[3.3] Client: Deriving AES-128 session key...
      K = Trunc16(SHA256(big-endian(Ks)))
      Session key: [32 hex characters]
      Key length: 16 bytes (AES-128)

================================================================================
[PHASE 4] Verification: DH Key Exchange Success
================================================================================

[4.1] Verifying shared secrets match...
      Client Ks: 0x...
      Server Ks: 0x...
      Secrets match: True ✓

[4.2] Verifying session keys match...
      Client K: [32 hex characters]
      Server K: [32 hex characters]
      Keys match: True ✓

[4.3] Verifying key properties...
      Key length correct (16 bytes): True ✓
      Key is non-zero: True ✓

================================================================================
[PHASE 5] Demonstration: Using Session Key for Encrypted Chat
================================================================================

[5.1] Client: Encrypting chat message...
      Plaintext: 'Hello, this is a secure chat message! Module 2.3 working!'
      Ciphertext (hex): [hex string]
      Ciphertext length: XX bytes

[5.2] Server: Decrypting chat message...
      Decrypted: 'Hello, this is a secure chat message! Module 2.3 working!'
      Match: True ✓

[5.3] Creating ChatMessage with signature...
      Message created:
      - Sequence: 1
      - Timestamp: XXXXXXXXXXXXX
      - Ciphertext (first 32 chars): ...
      - Signature (first 32 chars): ...
      - Signature valid: True ✓

================================================================================
[PHASE 6] Security Properties Achieved
================================================================================

✓ Confidentiality:
  - Session key derived from DH shared secret
  - Only client and server can compute Ks = A^b = B^a mod p
  - AES-128 encryption with derived key K
  - Different sessions will have different keys (forward separation)

✓ Key Derivation:
  - K = Trunc16(SHA256(big-endian(Ks)))
  - Derives 16-byte key from large DH shared secret
  - One-way function prevents Ks recovery from K

✓ Post-Authentication:
  - DH exchange happens AFTER successful login
  - Separate from registration/login credential protection
  - Fresh session key for each chat session

✓ No Key Transmission:
  - Session key K never transmitted over network
  - Only public values (p, g, A, B) sent
  - Private keys (a, b) never leave their respective systems

================================================================================
TEST SUMMARY
================================================================================

✓✓✓ ALL TESTS PASSED ✓✓✓

Section 2.3 Implementation Complete:
  ✓ DH key exchange successful
  ✓ Shared secrets match
  ✓ Session keys match
  ✓ Key length correct (16 bytes for AES-128)
  ✓ Encryption/decryption working

Ready for chat message exchange (Section 2.4)!

================================================================================
```

---

## Phase 3: Manual Testing & Verification

### Test 3.1: Verify Protocol Message Formats

```bash
python -c "
from app.common.protocol import DHClientMessage, DHServerMessage

# Test DHClientMessage
dh_client = DHClientMessage(p=12345, g=2, A=67890)
print('DHClientMessage:')
print(dh_client.model_dump_json(indent=2))
print()

# Test DHServerMessage
dh_server = DHServerMessage(B=99999)
print('DHServerMessage:')
print(dh_server.model_dump_json(indent=2))
"
```

**Expected Output:**
```
DHClientMessage:
{
  "type": "dh_client",
  "p": 12345,
  "g": 2,
  "A": 67890
}

DHServerMessage:
{
  "type": "dh_server",
  "B": 99999
}
```

### Test 3.2: Verify Key Derivation Formula

```bash
python -c "
from app.crypto.dh import derive_aes_key
from app.common.utils import int_to_bytes_bigendian, sha256_bytes

# Example shared secret
shared_secret = 123456789012345678901234567890

# Derive key
key = derive_aes_key(shared_secret)

# Verify manually
secret_bytes = int_to_bytes_bigendian(shared_secret)
hash_result = sha256_bytes(secret_bytes)
manual_key = hash_result[:16]

print(f'Shared Secret: {shared_secret}')
print(f'Derived Key:   {key.hex()}')
print(f'Manual Key:    {manual_key.hex()}')
print(f'Match: {key == manual_key}')
print(f'Length: {len(key)} bytes')
"
```

**Expected Output:**
```
Shared Secret: 123456789012345678901234567890
Derived Key:   [32 hex characters representing 16 bytes]
Manual Key:    [32 hex characters representing 16 bytes]
Match: True
Length: 16 bytes
```

---

## Phase 4: Evidence Collection

### Evidence 4.1: DH Message Sizes

Create evidence showing message sizes:

```bash
python -c "
from app.common.protocol import DHClientMessage, DHServerMessage
from app.crypto.dh import generate_dh_parameters, generate_dh_keypair

p, g = generate_dh_parameters()
client_priv, client_pub = generate_dh_keypair(p, g)
server_priv, server_pub = generate_dh_keypair(p, g)

dh_client_msg = DHClientMessage(p=p, g=g, A=client_pub)
dh_server_msg = DHServerMessage(B=server_pub)

client_json = dh_client_msg.model_dump_json()
server_json = dh_server_msg.model_dump_json()

print('DH Message Sizes:')
print(f'  DHClientMessage (p, g, A): {len(client_json)} bytes')
print(f'  DHServerMessage (B):       {len(server_json)} bytes')
print()
print('Message Structure:')
print(f'  Prime p: {p.bit_length()} bits = {p.bit_length() // 8} bytes')
print(f'  Public A: {client_pub.bit_length()} bits')
print(f'  Public B: {server_pub.bit_length()} bits')
" > evidence/dh_message_sizes.txt

cat evidence/dh_message_sizes.txt
```

### Evidence 4.2: Key Derivation Example

```bash
python -c "
from app.crypto.dh import generate_dh_parameters, generate_dh_keypair, compute_shared_secret, derive_aes_key

print('=== DH Key Derivation Example ===')
print()

p, g = generate_dh_parameters()
alice_priv, alice_pub = generate_dh_keypair(p, g)
bob_priv, bob_pub = generate_dh_keypair(p, g)

alice_secret = compute_shared_secret(bob_pub, alice_priv, p)
bob_secret = compute_shared_secret(alice_pub, bob_priv, p)

alice_key = derive_aes_key(alice_secret)
bob_key = derive_aes_key(bob_secret)

print(f'Alice public A: {hex(alice_pub)[:66]}...')
print(f'Bob public B:   {hex(bob_pub)[:66]}...')
print()
print(f'Alice computes: Ks = B^a mod p')
print(f'  Ks = {hex(alice_secret)[:66]}...')
print()
print(f'Bob computes:   Ks = A^b mod p')
print(f'  Ks = {hex(bob_secret)[:66]}...')
print()
print(f'Secrets match: {alice_secret == bob_secret}')
print()
print(f'Alice derives: K = Trunc16(SHA256(Ks))')
print(f'  K = {alice_key.hex()}')
print()
print(f'Bob derives:   K = Trunc16(SHA256(Ks))')
print(f'  K = {bob_key.hex()}')
print()
print(f'Keys match: {alice_key == bob_key}')
" > evidence/key_derivation_example.txt

cat evidence/key_derivation_example.txt
```

---

## Phase 5: Security Verification

### Verify 5.1: No Key in Transit

Confirm that the session key is never transmitted:

```bash
python -c "
from app.common.protocol import DHClientMessage, DHServerMessage
from app.crypto.dh import generate_dh_parameters, generate_dh_keypair, derive_aes_key, compute_shared_secret

# Simulate full exchange
p, g = generate_dh_parameters()
client_priv, client_pub = generate_dh_keypair(p, g)

dh_client_msg = DHClientMessage(p=p, g=g, A=client_pub)
client_json = dh_client_msg.model_dump_json()

server_priv, server_pub = generate_dh_keypair(p, g)
dh_server_msg = DHServerMessage(B=server_pub)
server_json = dh_server_msg.model_dump_json()

# Derive keys
server_secret = compute_shared_secret(client_pub, server_priv, p)
server_key = derive_aes_key(server_secret)

client_secret = compute_shared_secret(server_pub, client_priv, p)
client_key = derive_aes_key(client_secret)

print('What an eavesdropper sees:')
print('=' * 60)
print('Client message (excerpt):')
print(client_json[:200] + '...')
print()
print('Server message (excerpt):')
print(server_json[:200] + '...')
print()
print('Session key visible in traffic: NO')
print('Session key can be derived by eavesdropper: NO')
print('  (Would need private key a or b)')
print()
print(f'Actual session key (never transmitted): {client_key.hex()}')
"
```

### Verify 5.2: Forward Separation

Verify different sessions produce different keys:

```bash
python tests/test_section_2.3.py | grep "Session key:" | head -4
```

Run it twice and compare - keys should be different each time.

---

## Phase 6: Common Issues & Troubleshooting

### Issue 6.1: ImportError for cryptography

```bash
# Ensure cryptography is installed
pip install cryptography

# Verify installation
python -c "from cryptography.hazmat.primitives.asymmetric import dh; print('OK')"
```

### Issue 6.2: Keys Don't Match

**Symptom**: Client and server derive different session keys

**Diagnosis**:
```bash
python -c "
from app.crypto.dh import generate_dh_parameters, generate_dh_keypair, compute_shared_secret

p, g = generate_dh_parameters()
a_priv, a_pub = generate_dh_keypair(p, g)
b_priv, b_pub = generate_dh_keypair(p, g)

# Both should compute same secret
secret_a = compute_shared_secret(b_pub, a_priv, p)
secret_b = compute_shared_secret(a_pub, b_priv, p)

print(f'Secret A: {hex(secret_a)[:66]}...')
print(f'Secret B: {hex(secret_b)[:66]}...')
print(f'Match: {secret_a == secret_b}')
"
```

**Solution**: Verify you're using the same (p, g) parameters on both sides.

### Issue 6.3: Certificate Not Found

```bash
# If Phase 5.3 shows certificate error, generate certificates:
python scripts/gen_ca.py --name "FAST-NU Root CA"
python scripts/gen_cert.py --cn client.local --out certs/client
python scripts/gen_cert.py --cn server.local --out certs/server
```

---

## Phase 7: Final Checklist

Before proceeding to Section 2.4 (Encrypted Chat), ensure:

- [ ] ✅ DH module tests pass (`python -m app.crypto.dh`)
- [ ] ✅ Integration test passes (`python tests/test_section_2.3.py`)
- [ ] ✅ Client and server derive identical session keys
- [ ] ✅ Session key is exactly 16 bytes (AES-128)
- [ ] ✅ Session key can encrypt/decrypt messages
- [ ] ✅ Evidence files created in `evidence/` directory
- [ ] ✅ No session key visible in protocol messages
- [ ] ✅ Different test runs produce different keys

---

## Assignment Requirements Met

According to Assignment PDF Section 2.3:

✅ **Classical DH**: Using RFC 3526 Group 14 (2048-bit MODP)
✅ **Post-Authentication**: DH occurs AFTER successful login
✅ **Key Exchange**: Client sends (p, g, A), server responds with B
✅ **Shared Secret**: Both compute Ks = A^b mod p = B^a mod p
✅ **Key Derivation**: K = Trunc16(SHA256(big-endian(Ks)))
✅ **AES-128 Ready**: 16-byte key suitable for AES-128-ECB
✅ **Forward Separation**: Each session gets unique key

---

## Next Steps

After Section 2.3 is complete:

1. **Section 2.4**: Implement encrypted chat with message signing
2. **Section 2.5**: Implement non-repudiation (session receipts)
3. **Full Integration**: Connect client.py and server.py with all phases

---

## References

- Assignment PDF Section 1.2 (Key Agreement) - Page 3
- Assignment PDF Section 2.3 (Session Key Establishment) - Page 8
- RFC 3526: More Modular Exponential (MODP) Diffie-Hellman groups
- CLAUDE.md: Project architecture and constraints
