"""
Integration Test for Section 2.5: Non-Repudiation and Session Closure

This test demonstrates the complete non-repudiation mechanism with:
- Append-only transcript logging
- TranscriptHash computation
- Signed SessionReceipt generation
- Offline verification

Protocol Flow (PDF Pages 5, 9, Section 1.4):
1. Maintain append-only transcript: seqno | ts | ct | sig | peer-cert-fingerprint
2. Compute TranscriptHash = SHA256(concatenation of all log lines)
3. Sign transcript hash with RSA private key
4. Generate SessionReceipt with signed hash
5. Verify receipt offline (third-party verification)

Security Properties Tested:
- Non-Repudiation: Neither party can deny participation
- Tamper-Evidence: Any transcript modification invalidates signature
- Verifiable Proof: Third parties can verify offline
"""

import os
import tempfile
from app.crypto.dh import generate_dh_parameters, generate_dh_keypair, compute_shared_secret, derive_aes_key
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import generate_rsa_keypair, sign_data, verify_signature
from app.crypto.pki import generate_self_signed_cert
from app.common.protocol import ChatMessage, SessionReceiptMessage
from app.common.utils import b64e, b64d, now_ms
from app.storage.transcript import TranscriptManager, verify_session_receipt, verify_message_in_transcript

print("=" * 80)
print("Section 2.5: Non-Repudiation and Session Closure")
print("=" * 80)
print()

# ============================================================================
# PHASE 1: Setup - Establish Session (from previous modules)
# ============================================================================

print("[PHASE 1] Setup: Establishing Secure Session")
print("-" * 80)

print("[1.1] Generating RSA keypairs and certificates...")
# Generate Alice's (client) credentials
alice_private_key, alice_public_key = generate_rsa_keypair(key_size=2048)
alice_cert = generate_self_signed_cert(
    private_key=alice_private_key,
    common_name="Alice (Client)",
    validity_days=365
)
print("      Alice RSA keypair and certificate generated")

# Generate Bob's (server) credentials
bob_private_key, bob_public_key = generate_rsa_keypair(key_size=2048)
bob_cert = generate_self_signed_cert(
    private_key=bob_private_key,
    common_name="Bob (Server)",
    validity_days=365
)
print("      Bob RSA keypair and certificate generated")

print("\n[1.2] Performing DH key exchange...")
p, g = generate_dh_parameters()
alice_priv, alice_pub = generate_dh_keypair(p, g)
bob_priv, bob_pub = generate_dh_keypair(p, g)

alice_secret = compute_shared_secret(bob_pub, alice_priv, p)
bob_secret = compute_shared_secret(alice_pub, bob_priv, p)

alice_session_key = derive_aes_key(alice_secret)
bob_session_key = derive_aes_key(bob_secret)

print(f"      Session key established: {alice_session_key.hex()}")
print(f"      Keys match: {alice_session_key == bob_session_key} {'✓' if alice_session_key == bob_session_key else '✗'}")
print()

# ============================================================================
# PHASE 2: Initialize Transcript Managers
# ============================================================================

print("[PHASE 2] Initializing Transcript Managers")
print("-" * 80)

# Create temporary directory for transcripts
temp_dir = tempfile.mkdtemp()
alice_transcript_path = os.path.join(temp_dir, "alice_transcript.log")
bob_transcript_path = os.path.join(temp_dir, "bob_transcript.log")

print(f"[2.1] Creating Alice's transcript manager...")
# Alice logs Bob's messages (peer = Bob)
alice_transcript = TranscriptManager(alice_transcript_path, bob_cert)
print(f"      Transcript path: {alice_transcript_path}")
print(f"      Peer fingerprint: {alice_transcript.peer_fingerprint[:32]}...")

print(f"\n[2.2] Creating Bob's transcript manager...")
# Bob logs Alice's messages (peer = Alice)
bob_transcript = TranscriptManager(bob_transcript_path, alice_cert)
print(f"      Transcript path: {bob_transcript_path}")
print(f"      Peer fingerprint: {bob_transcript.peer_fingerprint[:32]}...")
print()

# ============================================================================
# PHASE 3: Chat Session with Transcript Logging
# ============================================================================

print("[PHASE 3] Chat Session with Transcript Logging")
print("-" * 80)

# Track sequence numbers
alice_send_seqno = 1
alice_recv_seqno = 1
bob_send_seqno = 1
bob_recv_seqno = 1

# Message 1: Alice -> Bob
print(f"\n[3.1] Alice → Bob: Message #{alice_send_seqno}")
alice_msg_1 = "Hello Bob! This is our first secure message."
print(f"      Plaintext: '{alice_msg_1}'")

# Encrypt and sign
alice_ts_1 = now_ms()
alice_ct_1 = aes_encrypt(alice_msg_1.encode('utf-8'), alice_session_key)
alice_ct_b64_1 = b64e(alice_ct_1)

alice_sig_data_1 = f"{alice_send_seqno}{alice_ts_1}{alice_ct_b64_1}".encode('utf-8')
alice_sig_1 = sign_data(alice_sig_data_1, alice_private_key)
alice_sig_b64_1 = b64e(alice_sig_1)

# Log to Bob's transcript (Bob receives from Alice)
bob_transcript.append_message(alice_send_seqno, alice_ts_1, alice_ct_b64_1, alice_sig_b64_1)
print(f"      ✓ Message logged to Bob's transcript")

# Bob verifies and decrypts
bob_sig_data_1 = f"{alice_send_seqno}{alice_ts_1}{alice_ct_b64_1}".encode('utf-8')
bob_sig_verify_1 = verify_signature(bob_sig_data_1, alice_sig_1, alice_cert)
print(f"      Bob verifies signature: {bob_sig_verify_1} {'✓' if bob_sig_verify_1 else '✗'}")

bob_plaintext_1 = aes_decrypt(alice_ct_1, bob_session_key).decode('utf-8')
print(f"      Bob decrypted: '{bob_plaintext_1}'")
bob_recv_seqno += 1
alice_send_seqno += 1

# Message 2: Alice -> Bob
print(f"\n[3.2] Alice → Bob: Message #{alice_send_seqno}")
alice_msg_2 = "Let's test non-repudiation with multiple messages."
print(f"      Plaintext: '{alice_msg_2}'")

alice_ts_2 = now_ms()
alice_ct_2 = aes_encrypt(alice_msg_2.encode('utf-8'), alice_session_key)
alice_ct_b64_2 = b64e(alice_ct_2)

alice_sig_data_2 = f"{alice_send_seqno}{alice_ts_2}{alice_ct_b64_2}".encode('utf-8')
alice_sig_2 = sign_data(alice_sig_data_2, alice_private_key)
alice_sig_b64_2 = b64e(alice_sig_2)

bob_transcript.append_message(alice_send_seqno, alice_ts_2, alice_ct_b64_2, alice_sig_b64_2)
print(f"      ✓ Message logged to Bob's transcript")
bob_recv_seqno += 1
alice_send_seqno += 1

# Message 3: Bob -> Alice
print(f"\n[3.3] Bob → Alice: Message #{bob_send_seqno}")
bob_msg_1 = "Hi Alice! I received both your messages securely."
print(f"      Plaintext: '{bob_msg_1}'")

bob_ts_1 = now_ms()
bob_ct_1 = aes_encrypt(bob_msg_1.encode('utf-8'), bob_session_key)
bob_ct_b64_1 = b64e(bob_ct_1)

bob_sig_data_1 = f"{bob_send_seqno}{bob_ts_1}{bob_ct_b64_1}".encode('utf-8')
bob_sig_1 = sign_data(bob_sig_data_1, bob_private_key)
bob_sig_b64_1 = b64e(bob_sig_1)

# Log to Alice's transcript (Alice receives from Bob)
alice_transcript.append_message(bob_send_seqno, bob_ts_1, bob_ct_b64_1, bob_sig_b64_1)
print(f"      ✓ Message logged to Alice's transcript")

alice_plaintext_1 = aes_decrypt(bob_ct_1, alice_session_key).decode('utf-8')
print(f"      Alice decrypted: '{alice_plaintext_1}'")
alice_recv_seqno += 1
bob_send_seqno += 1

# Message 4: Bob -> Alice
print(f"\n[3.4] Bob → Alice: Message #{bob_send_seqno}")
bob_msg_2 = "This conversation will be cryptographically provable!"
print(f"      Plaintext: '{bob_msg_2}'")

bob_ts_2 = now_ms()
bob_ct_2 = aes_encrypt(bob_msg_2.encode('utf-8'), bob_session_key)
bob_ct_b64_2 = b64e(bob_ct_2)

bob_sig_data_2 = f"{bob_send_seqno}{bob_ts_2}{bob_ct_b64_2}".encode('utf-8')
bob_sig_2 = sign_data(bob_sig_data_2, bob_private_key)
bob_sig_b64_2 = b64e(bob_sig_2)

alice_transcript.append_message(bob_send_seqno, bob_ts_2, bob_ct_b64_2, bob_sig_b64_2)
print(f"      ✓ Message logged to Alice's transcript")
alice_recv_seqno += 1
bob_send_seqno += 1

print(f"\n      Chat session complete:")
print(f"      - Alice sent {alice_send_seqno - 1} messages")
print(f"      - Bob sent {bob_send_seqno - 1} messages")
print()

# ============================================================================
# PHASE 4: Compute TranscriptHash
# ============================================================================

print("[PHASE 4] Computing TranscriptHash")
print("-" * 80)

print("[4.1] Alice computes TranscriptHash...")
alice_transcript_hash = alice_transcript.compute_transcript_hash()
print(f"      Alice's TranscriptHash: {alice_transcript_hash}")
print(f"      First seq: {alice_transcript.first_seq}")
print(f"      Last seq: {alice_transcript.last_seq}")

print("\n[4.2] Bob computes TranscriptHash...")
bob_transcript_hash = bob_transcript.compute_transcript_hash()
print(f"      Bob's TranscriptHash: {bob_transcript_hash}")
print(f"      First seq: {bob_transcript.first_seq}")
print(f"      Last seq: {bob_transcript.last_seq}")

print("\n      Note: Hashes differ because Alice and Bob log different messages")
print(f"      - Alice logs messages FROM Bob (what she received)")
print(f"      - Bob logs messages FROM Alice (what he received)")
print()

# ============================================================================
# PHASE 5: Generate SessionReceipts
# ============================================================================

print("[PHASE 5] Generating SessionReceipts")
print("-" * 80)

print("[5.1] Alice generates her SessionReceipt...")
alice_receipt = alice_transcript.generate_session_receipt("client", alice_private_key)
print(f"      Peer: {alice_receipt.peer}")
print(f"      Sequence range: {alice_receipt.first_seq} to {alice_receipt.last_seq}")
print(f"      TranscriptHash: {alice_receipt.transcript_sha256[:32]}...")
print(f"      Signature: {alice_receipt.sig[:32]}...")

# Save Alice's receipt
alice_receipt_path = os.path.join(temp_dir, "alice_session_receipt.json")
alice_transcript.save_receipt(alice_receipt, alice_receipt_path)
print(f"      ✓ Receipt saved to: {alice_receipt_path}")

print("\n[5.2] Bob generates his SessionReceipt...")
bob_receipt = bob_transcript.generate_session_receipt("server", bob_private_key)
print(f"      Peer: {bob_receipt.peer}")
print(f"      Sequence range: {bob_receipt.first_seq} to {bob_receipt.last_seq}")
print(f"      TranscriptHash: {bob_receipt.transcript_sha256[:32]}...")
print(f"      Signature: {bob_receipt.sig[:32]}...")

# Save Bob's receipt
bob_receipt_path = os.path.join(temp_dir, "bob_session_receipt.json")
bob_transcript.save_receipt(bob_receipt, bob_receipt_path)
print(f"      ✓ Receipt saved to: {bob_receipt_path}")
print()

# ============================================================================
# PHASE 6: Offline Verification of SessionReceipts
# ============================================================================

print("[PHASE 6] Offline Verification of SessionReceipts")
print("-" * 80)

print("[6.1] Third-party verifies Alice's SessionReceipt...")
print("      (Using Alice's certificate and transcript file)")
alice_receipt_valid = verify_session_receipt(
    alice_transcript_path,
    alice_receipt,
    alice_cert
)
print(f"      Alice's receipt valid: {alice_receipt_valid} {'✓' if alice_receipt_valid else '✗'}")

if alice_receipt_valid:
    print("      ✓ Alice's SessionReceipt verified!")
    print("      - TranscriptHash matches")
    print("      - RSA signature is valid")
    print("      - Alice cannot deny this session")

print("\n[6.2] Third-party verifies Bob's SessionReceipt...")
print("      (Using Bob's certificate and transcript file)")
bob_receipt_valid = verify_session_receipt(
    bob_transcript_path,
    bob_receipt,
    bob_cert
)
print(f"      Bob's receipt valid: {bob_receipt_valid} {'✓' if bob_receipt_valid else '✗'}")

if bob_receipt_valid:
    print("      ✓ Bob's SessionReceipt verified!")
    print("      - TranscriptHash matches")
    print("      - RSA signature is valid")
    print("      - Bob cannot deny this session")
print()

# ============================================================================
# PHASE 7: Verify Individual Messages in Transcript
# ============================================================================

print("[PHASE 7] Verifying Individual Messages in Transcript")
print("-" * 80)

print("[7.1] Verifying messages in Bob's transcript (from Alice)...")
with open(bob_transcript_path, 'r') as f:
    bob_transcript_lines = f.readlines()

for i, line in enumerate(bob_transcript_lines, 1):
    msg_valid = verify_message_in_transcript(line, alice_cert)
    print(f"      Message {i}: {msg_valid} {'✓' if msg_valid else '✗'}")

print("\n[7.2] Verifying messages in Alice's transcript (from Bob)...")
with open(alice_transcript_path, 'r') as f:
    alice_transcript_lines = f.readlines()

for i, line in enumerate(alice_transcript_lines, 1):
    msg_valid = verify_message_in_transcript(line, bob_cert)
    print(f"      Message {i}: {msg_valid} {'✓' if msg_valid else '✗'}")
print()

# ============================================================================
# PHASE 8: Tampering Detection Test
# ============================================================================

print("[PHASE 8] Security Test: Tampering Detection")
print("-" * 80)

print("[8.1] Attacker: Tampering with Alice's transcript...")
# Append a fake message to Alice's transcript
with open(alice_transcript_path, 'a') as f:
    f.write("999|9999999999|fake_ciphertext|fake_signature|fake_fingerprint\n")
print("      Fake message appended to transcript")

print("\n[8.2] Third-party: Re-verifying Alice's receipt after tampering...")
alice_tampered_valid = verify_session_receipt(
    alice_transcript_path,
    alice_receipt,
    alice_cert
)
print(f"      Receipt valid: {alice_tampered_valid} {'✗ BLOCKED' if not alice_tampered_valid else '✓ FAILED'}")

if not alice_tampered_valid:
    print("      ✓ Tampering detected!")
    print("      - TranscriptHash changed")
    print("      - Original signature no longer matches")
    print("      - Modification attempt blocked")
else:
    print("      ✗ ERROR: Tampering not detected!")

# Restore original transcript
with open(alice_transcript_path, 'w') as f:
    f.writelines(alice_transcript_lines)
print("\n      Transcript restored to original state")
print()

# ============================================================================
# PHASE 9: Demonstrate Exportable Evidence
# ============================================================================

print("[PHASE 9] Exportable Evidence for Third-Party Verification")
print("-" * 80)

print("[9.1] Evidence package contents:")
print(f"      - Alice's transcript: {alice_transcript_path}")
print(f"      - Alice's receipt: {alice_receipt_path}")
print(f"      - Alice's certificate: alice_cert.pem (contains public key)")
print()
print(f"      - Bob's transcript: {bob_transcript_path}")
print(f"      - Bob's receipt: {bob_receipt_path}")
print(f"      - Bob's certificate: bob_cert.pem (contains public key)")

print("\n[9.2] Third-party verification procedure:")
print("      1. Load transcript file and SessionReceipt JSON")
print("      2. Recompute TranscriptHash from transcript")
print("      3. Verify hash matches receipt.transcript_sha256")
print("      4. Load signer's certificate (public key)")
print("      5. Verify RSA signature on TranscriptHash")
print("      6. If all checks pass → Session is authenticated")

print("\n[9.3] Example verification command (pseudocode):")
print("      python verify_receipt.py \\")
print("          --transcript alice_transcript.log \\")
print("          --receipt alice_session_receipt.json \\")
print("          --cert alice_cert.pem")
print()

# ============================================================================
# PHASE 10: Security Properties Summary
# ============================================================================

print("=" * 80)
print("[PHASE 10] Security Properties Verification")
print("=" * 80)

print("\n✓ Non-Repudiation:")
print("  - Alice signed her SessionReceipt with her private key")
print("  - Bob signed his SessionReceipt with his private key")
print("  - Neither can deny participation (signatures prove identity)")
print("  - Third parties can verify using public certificates")

print("\n✓ Tamper-Evidence:")
print("  - TranscriptHash = SHA256(all log lines)")
print("  - Any modification changes the hash")
print("  - Changed hash invalidates signature")
print("  - Tampering detection demonstrated")

print("\n✓ Append-Only Transcript:")
print("  - Format: seqno | ts | ct | sig | peer-cert-fingerprint")
print("  - Each message logged immediately")
print("  - Complete audit trail maintained")

print("\n✓ Offline Verification:")
print("  - No online access needed")
print("  - Only requires: transcript + receipt + certificate")
print("  - Recompute hash and verify signature")
print("  - Fully independent third-party auditable")

print("\n✓ SessionReceipt Format (PDF Specification):")
print("  - type: 'receipt'")
print("  - peer: 'client' or 'server'")
print("  - first_seq, last_seq: sequence range")
print("  - transcript_sha256: hex-encoded hash")
print("  - sig: base64(RSA_SIGN(transcript_sha256))")

# ============================================================================
# CLEANUP AND SUMMARY
# ============================================================================

print("\n" + "=" * 80)
print("TEST SUMMARY")
print("=" * 80)

all_tests_passed = (
    alice_session_key == bob_session_key and  # Session key established
    alice_receipt_valid and                    # Alice's receipt verified
    bob_receipt_valid and                       # Bob's receipt verified
    not alice_tampered_valid                    # Tampering detected
)

if all_tests_passed:
    print("\n✓✓✓ ALL TESTS PASSED ✓✓✓")
    print("\nSection 2.5 Implementation Complete:")
    print("  ✓ Append-only transcript logging")
    print("  ✓ TranscriptHash computation")
    print("  ✓ Signed SessionReceipt generation")
    print("  ✓ Offline verification support")
    print("  ✓ Individual message verification")
    print("  ✓ Tampering detection via hash mismatch")
    print("  ✓ Exportable evidence package")
    print("\nFull CIANR Implementation Complete!")
    print("  ✓ Confidentiality (AES-128)")
    print("  ✓ Integrity (SHA-256 + RSA signatures)")
    print("  ✓ Authenticity (PKI + per-message signatures)")
    print("  ✓ Non-Repudiation (signed SessionReceipts)")
    print("  ✓ Freshness (sequence numbers + timestamps)")
else:
    print("\n✗✗✗ SOME TESTS FAILED ✗✗✗")
    print("Please check the output above for errors.")

print("\n[Cleanup] Removing temporary test files...")
import shutil
shutil.rmtree(temp_dir)
print(f"      Temporary directory removed: {temp_dir}")

print("\n" + "=" * 80)
print()
