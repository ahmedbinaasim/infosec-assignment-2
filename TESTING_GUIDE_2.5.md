# Testing Guide: Section 2.5 - Non-Repudiation and Session Closure

**Module:** Section 2.5 - Non-Repudiation and Session Closure
**Test File:** `tests/test_section_2.5.py`
**PDF Reference:** Pages 5, 9 (Section 1.4, Section 2.5)

---

## Overview

This guide demonstrates the **non-repudiation mechanism** that ensures neither party can deny participation in a chat session. The implementation provides:

- **Append-only transcript logging** of all messages
- **TranscriptHash computation** for tamper-evidence
- **Signed SessionReceipts** for cryptographic proof
- **Offline verification** by third parties

---

## Security Properties Tested

### 1. Non-Repudiation
- Each participant signs their SessionReceipt with their RSA private key
- Third parties can verify using public certificates
- Neither party can deny participation

### 2. Tamper-Evidence
- Any modification to transcript changes TranscriptHash
- Changed hash invalidates the signature
- Tampering is immediately detectable

### 3. Offline Verification
- No online access required
- Only needs: transcript file + SessionReceipt JSON + certificate
- Fully independent third-party auditable

### 4. Complete Audit Trail
- Every message logged with: seqno | ts | ct | sig | peer-cert-fingerprint
- Sequence numbers ensure completeness
- Timestamps provide chronological order

---

## Test Execution

### Run the Integration Test

```bash
# Activate virtual environment
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# Run Section 2.5 test
python tests/test_section_2.5.py
```

### Expected Output Structure

The test performs **10 phases**:

1. **PHASE 1:** Setup - Establish secure session (DH key exchange)
2. **PHASE 2:** Initialize transcript managers for Alice and Bob
3. **PHASE 3:** Chat session with transcript logging (4 messages)
4. **PHASE 4:** Compute TranscriptHash
5. **PHASE 5:** Generate SessionReceipts
6. **PHASE 6:** Offline verification of receipts
7. **PHASE 7:** Verify individual messages in transcripts
8. **PHASE 8:** Tampering detection test
9. **PHASE 9:** Demonstrate exportable evidence
10. **PHASE 10:** Security properties summary

---

## Detailed Protocol Flow

### Phase 1: Session Establishment

```
[1.1] Generating RSA keypairs and certificates...
      Alice RSA keypair and certificate generated
      Bob RSA keypair and certificate generated

[1.2] Performing DH key exchange...
      Session key established: <16-byte hex>
      Keys match: True ✓
```

**Verification:**
- ✓ Both parties derive identical session key
- ✓ Certificates generated for signing

---

### Phase 2: Transcript Initialization

```
[2.1] Creating Alice's transcript manager...
      Transcript path: /tmp/.../alice_transcript.log
      Peer fingerprint: <SHA256 of Bob's cert>...

[2.2] Creating Bob's transcript manager...
      Transcript path: /tmp/.../bob_transcript.log
      Peer fingerprint: <SHA256 of Alice's cert>...
```

**Key Concept:**
- Alice logs messages FROM Bob (what she received)
- Bob logs messages FROM Alice (what he received)
- Each transcript records the peer's cert fingerprint

**Transcript Format (PDF Page 5, 9):**
```
seqno | timestamp | ciphertext | signature | peer-cert-fingerprint
```

---

### Phase 3: Chat Session with Logging

```
[3.1] Alice → Bob: Message #1
      Plaintext: 'Hello Bob! This is our first secure message.'
      ✓ Message logged to Bob's transcript
      Bob verifies signature: True ✓
      Bob decrypted: 'Hello Bob! This is our first secure message.'

[3.2] Alice → Bob: Message #2
      Plaintext: 'Let's test non-repudiation with multiple messages.'
      ✓ Message logged to Bob's transcript

[3.3] Bob → Alice: Message #1
      Plaintext: 'Hi Alice! I received both your messages securely.'
      ✓ Message logged to Alice's transcript
      Alice decrypted: 'Hi Alice! I received both your messages securely.'

[3.4] Bob → Alice: Message #2
      Plaintext: 'This conversation will be cryptographically provable!'
      ✓ Message logged to Alice's transcript

      Chat session complete:
      - Alice sent 2 messages
      - Bob sent 2 messages
```

**Verification:**
- ✓ All messages encrypted with AES-128
- ✓ All messages signed with sender's RSA private key
- ✓ All messages logged to recipient's transcript
- ✓ Signatures verified before logging

---

### Phase 4: TranscriptHash Computation

```
[4.1] Alice computes TranscriptHash...
      Alice's TranscriptHash: <64-char hex SHA256>
      First seq: 1
      Last seq: 2

[4.2] Bob computes TranscriptHash...
      Bob's TranscriptHash: <64-char hex SHA256>
      First seq: 1
      Last seq: 2

      Note: Hashes differ because Alice and Bob log different messages
      - Alice logs messages FROM Bob (what she received)
      - Bob logs messages FROM Alice (what he received)
```

**PDF Specification (Page 5, 9):**
```
TranscriptHash = SHA256(concatenation of all log lines)
```

**Verification:**
- ✓ Each party computes hash of their transcript
- ✓ Hashes differ (Alice logs Bob's msgs, Bob logs Alice's msgs)
- ✓ Hash covers entire file content

---

### Phase 5: SessionReceipt Generation

```
[5.1] Alice generates her SessionReceipt...
      Peer: client
      Sequence range: 1 to 2
      TranscriptHash: <first 32 chars>...
      Signature: <first 32 chars>...
      ✓ Receipt saved to: alice_session_receipt.json

[5.2] Bob generates his SessionReceipt...
      Peer: server
      Sequence range: 1 to 2
      TranscriptHash: <first 32 chars>...
      Signature: <first 32 chars>...
      ✓ Receipt saved to: bob_session_receipt.json
```

**SessionReceipt Format (PDF Page 5, 9):**
```json
{
  "type": "receipt",
  "peer": "client|server",
  "first_seq": 1,
  "last_seq": 2,
  "transcript_sha256": "<64-char hex>",
  "sig": "<base64(RSA_SIGN(transcript_sha256))>"
}
```

**Verification:**
- ✓ Receipt contains transcript hash
- ✓ Receipt signed with sender's RSA private key
- ✓ Receipt saved as JSON for offline verification

---

### Phase 6: Offline Verification

```
[6.1] Third-party verifies Alice's SessionReceipt...
      (Using Alice's certificate and transcript file)
      Alice's receipt valid: True ✓
      ✓ Alice's SessionReceipt verified!
      - TranscriptHash matches
      - RSA signature is valid
      - Alice cannot deny this session

[6.2] Third-party verifies Bob's SessionReceipt...
      (Using Bob's certificate and transcript file)
      Bob's receipt valid: True ✓
      ✓ Bob's SessionReceipt verified!
      - TranscriptHash matches
      - RSA signature is valid
      - Bob cannot deny this session
```

**Verification Process (PDF Page 9-10):**
1. Load transcript file and SessionReceipt JSON
2. Recompute TranscriptHash from transcript
3. Verify hash matches `receipt.transcript_sha256`
4. Extract signature from receipt
5. Verify RSA signature using signer's certificate
6. If all pass → Session authenticated, non-repudiation proven

**Verification:**
- ✓ Recomputed hash matches receipt hash
- ✓ RSA signature verified with public key
- ✓ No online access required
- ✓ Third-party can independently verify

---

### Phase 7: Individual Message Verification

```
[7.1] Verifying messages in Bob's transcript (from Alice)...
      Message 1: True ✓
      Message 2: True ✓

[7.2] Verifying messages in Alice's transcript (from Bob)...
      Message 1: True ✓
      Message 2: True ✓
```

**Per-Message Verification:**
- Parse transcript line: `seqno|ts|ct|sig|fingerprint`
- Recompute signature data: `SHA256(seqno || ts || ct)`
- Verify RSA signature using sender's certificate

**Verification:**
- ✓ Every message signature is valid
- ✓ Each message traceable to sender
- ✓ Fine-grained audit capability

---

### Phase 8: Tampering Detection

```
[8.1] Attacker: Tampering with Alice's transcript...
      Fake message appended to transcript

[8.2] Third-party: Re-verifying Alice's receipt after tampering...
      Receipt valid: False ✗ BLOCKED
      ✓ Tampering detected!
      - TranscriptHash changed
      - Original signature no longer matches
      - Modification attempt blocked

      Transcript restored to original state
```

**Attack Scenario:**
1. Attacker appends fake message to transcript
2. TranscriptHash changes
3. Original signature no longer matches new hash
4. Verification fails

**Verification:**
- ✓ Tampering detected via hash mismatch
- ✓ Original signature invalidated
- ✓ Tamper-evidence property demonstrated

---

### Phase 9: Exportable Evidence

```
[9.1] Evidence package contents:
      - Alice's transcript: alice_transcript.log
      - Alice's receipt: alice_session_receipt.json
      - Alice's certificate: alice_cert.pem (contains public key)

      - Bob's transcript: bob_transcript.log
      - Bob's receipt: bob_session_receipt.json
      - Bob's certificate: bob_cert.pem (contains public key)

[9.2] Third-party verification procedure:
      1. Load transcript file and SessionReceipt JSON
      2. Recompute TranscriptHash from transcript
      3. Verify hash matches receipt.transcript_sha256
      4. Load signer's certificate (public key)
      5. Verify RSA signature on TranscriptHash
      6. If all checks pass → Session is authenticated

[9.3] Example verification command (pseudocode):
      python verify_receipt.py \
          --transcript alice_transcript.log \
          --receipt alice_session_receipt.json \
          --cert alice_cert.pem
```

**Evidence Properties:**
- **Complete:** All messages logged
- **Verifiable:** RSA signatures prove authenticity
- **Portable:** JSON + log files are standard formats
- **Offline:** No server access needed

---

### Phase 10: Security Properties Summary

```
✓ Non-Repudiation:
  - Alice signed her SessionReceipt with her private key
  - Bob signed his SessionReceipt with his private key
  - Neither can deny participation (signatures prove identity)
  - Third parties can verify using public certificates

✓ Tamper-Evidence:
  - TranscriptHash = SHA256(all log lines)
  - Any modification changes the hash
  - Changed hash invalidates signature
  - Tampering detection demonstrated

✓ Append-Only Transcript:
  - Format: seqno | ts | ct | sig | peer-cert-fingerprint
  - Each message logged immediately
  - Complete audit trail maintained

✓ Offline Verification:
  - No online access needed
  - Only requires: transcript + receipt + certificate
  - Recompute hash and verify signature
  - Fully independent third-party auditable
```

---

## Final Test Summary

```
✓✓✓ ALL TESTS PASSED ✓✓✓

Section 2.5 Implementation Complete:
  ✓ Append-only transcript logging
  ✓ TranscriptHash computation
  ✓ Signed SessionReceipt generation
  ✓ Offline verification support
  ✓ Individual message verification
  ✓ Tampering detection via hash mismatch
  ✓ Exportable evidence package

Full CIANR Implementation Complete!
  ✓ Confidentiality (AES-128)
  ✓ Integrity (SHA-256 + RSA signatures)
  ✓ Authenticity (PKI + per-message signatures)
  ✓ Non-Repudiation (signed SessionReceipts)
  ✓ Freshness (sequence numbers + timestamps)
```

---

## Evidence Collection for Assignment Submission

### 1. Run the Test and Capture Output

```bash
python tests/test_section_2.5.py > section_2.5_output.txt 2>&1
```

### 2. Inspect Generated Files

The test creates temporary files during execution:
- `alice_transcript.log` - Alice's message log
- `bob_transcript.log` - Bob's message log
- `alice_session_receipt.json` - Alice's signed receipt
- `bob_session_receipt.json` - Bob's signed receipt

**Example Transcript Format:**
```
1|1700000000000|dGVzdF9jaXBoZXJ0ZXh0|c2lnbmF0dXJlX2Jhc2U2NA==|abc123...def
2|1700000001000|YW5vdGhlcl9jaXBoZXJ0ZXh0|YW5vdGhlcl9zaWduYXR1cmU=|abc123...def
```

**Example SessionReceipt JSON:**
```json
{
  "type": "receipt",
  "peer": "client",
  "first_seq": 1,
  "last_seq": 2,
  "transcript_sha256": "abcd1234...89ef",
  "sig": "base64_encoded_signature..."
}
```

### 3. Manual Verification Steps

**Step 1: Verify TranscriptHash**
```bash
# Compute SHA256 hash of transcript
sha256sum alice_transcript.log

# Compare with transcript_sha256 in alice_session_receipt.json
cat alice_session_receipt.json | grep transcript_sha256
```

**Step 2: Verify RSA Signature**
```python
from app.storage.transcript import verify_session_receipt
from app.crypto.pki import load_certificate
from app.common.protocol import SessionReceiptMessage

# Load receipt and certificate
with open('alice_session_receipt.json') as f:
    receipt = SessionReceiptMessage.model_validate_json(f.read())

cert = load_certificate('certs/alice_cert.pem')

# Verify
is_valid = verify_session_receipt('alice_transcript.log', receipt, cert)
print(f"Receipt valid: {is_valid}")
```

---

## Implementation Details

### 1. TranscriptManager Class

**Location:** `app/storage/transcript.py`

**Key Methods:**
- `append_message()` - Add message to append-only log
- `compute_transcript_hash()` - SHA256 of all lines
- `generate_session_receipt()` - Create signed receipt
- `save_receipt()` - Export receipt to JSON

**Usage Example:**
```python
from app.storage.transcript import TranscriptManager

# Initialize
manager = TranscriptManager("chat_transcript.log", peer_cert)

# Log messages
manager.append_message(seqno=1, ts=now_ms(), ct=ct_b64, sig=sig_b64)

# Generate receipt
receipt = manager.generate_session_receipt("client", private_key)
manager.save_receipt(receipt, "session_receipt.json")
```

### 2. Integration with Chat Functions

**Client/Server Functions Enhanced:**
- `send_chat_message()` - Now accepts `transcript_manager` parameter
- `receive_chat_message()` - Now accepts `transcript_manager` parameter

**Usage Pattern:**
```python
# Send message with logging
send_chat_message(
    sock, plaintext, session_key, seqno, private_key,
    transcript_manager=manager  # Automatically logs
)

# Receive message with logging
plaintext, next_seq = receive_chat_message(
    sock, session_key, expected_seqno, peer_cert,
    transcript_manager=manager  # Automatically logs
)
```

### 3. Offline Verification Function

**Location:** `app/storage/transcript.py`

**Function:** `verify_session_receipt()`

**Process:**
1. Read transcript file
2. Compute SHA256(file_content)
3. Compare with receipt.transcript_sha256
4. Verify RSA signature using signer's certificate

---

## Common Issues and Troubleshooting

### Issue 1: TranscriptHash Mismatch

**Symptom:** Verification fails with hash mismatch

**Causes:**
- Transcript file modified after receipt generation
- Line endings changed (CRLF vs LF)
- Encoding issues

**Solution:**
- Ensure transcript is read in binary mode or with consistent encoding
- Use UTF-8 encoding consistently
- Don't modify transcript after receipt generation

### Issue 2: Signature Verification Fails

**Symptom:** RSA signature doesn't verify

**Causes:**
- Wrong certificate used for verification
- Receipt signed with different private key
- TranscriptHash corrupted

**Solution:**
- Verify you're using the correct signer's certificate
- Check that receipt was signed by the expected party
- Recompute TranscriptHash manually

### Issue 3: Empty Transcript

**Symptom:** No messages in transcript file

**Causes:**
- `transcript_manager` not passed to send/receive functions
- Transcript file path incorrect
- Permission issues

**Solution:**
- Pass `transcript_manager` parameter to all message functions
- Verify file path and permissions
- Check that `append_message()` is called

---

## PDF Specification Compliance

### Section 1.4: Non-Repudiation (Page 5)

**Requirement:** Maintain append-only transcript
- ✓ Implemented with `TranscriptManager.append_message()`
- ✓ Format: `seqno | ts | ct | sig | peer-cert-fingerprint`

**Requirement:** Compute TranscriptHash
- ✓ Implemented with `TranscriptManager.compute_transcript_hash()`
- ✓ Formula: `SHA256(concatenation of all log lines)`

**Requirement:** Sign transcript hash
- ✓ Implemented in `generate_session_receipt()`
- ✓ Uses RSA private key

**Requirement:** Generate SessionReceipt
- ✓ Format matches PDF specification exactly
- ✓ Fields: type, peer, first_seq, last_seq, transcript_sha256, sig

### Section 2.5: Non-Repudiation and Session Closure (Page 9)

**Requirement:** Offline verification
- ✓ Implemented with `verify_session_receipt()`
- ✓ No server access required

**Requirement:** Tampering detection
- ✓ Demonstrated in Phase 8 of test
- ✓ Modified transcript invalidates signature

**Requirement:** Exportable evidence
- ✓ JSON receipt format
- ✓ Standard log file format
- ✓ Third-party verifiable

---

## Grading Rubric Alignment

**Objective:** Integrity, Authenticity & Non-Repudiation (10% of grade)

**Excellent (10-8 points):**
- ✓ Per-message RSA signatures over SHA-256 digests
- ✓ Strict sequence number enforcement
- ✓ Append-only transcript maintained
- ✓ SessionReceipt (signed transcript hash) produced and exported
- ✓ Offline verification documented
- ✓ Message digests + signatures verified
- ✓ Receipt verified over transcript hash

**Evidence for Submission:**
1. Test output showing all phases passing
2. Sample transcript files
3. Sample SessionReceipt JSON files
4. Offline verification demonstration
5. Tampering detection demonstration

---

## Next Steps

After Section 2.5 is complete, the full SecureChat protocol is implemented:

- ✅ **Section 2.1:** PKI Setup and Certificate Validation
- ✅ **Section 2.2:** Registration and Login
- ✅ **Section 2.3:** Session Key Establishment
- ✅ **Section 2.4:** Encrypted Chat and Message Integrity
- ✅ **Section 2.5:** Non-Repudiation and Session Closure

**Remaining tasks:**
1. Integration testing with full client-server workflow
2. Wireshark capture for evidence
3. Attack demonstrations (replay, tampering, invalid certs)
4. Documentation and report writing

---

**End of Testing Guide - Section 2.5**
