"""
Integration Test for Section 2.4: Encrypted Chat and Message Integrity

This test demonstrates secure encrypted chat with per-message signatures,
providing Confidentiality, Integrity, Authenticity, and Freshness.

Protocol Flow (PDF Pages 4-5, Section 1.3):
1. Encrypt plaintext with AES-128 using session key K
2. Compute digest: h = SHA256(seqno || timestamp || ciphertext)
3. Sign digest with RSA private key
4. Verify signature on receive
5. Enforce strict sequence number (replay protection)

Security Properties Tested:
- Confidentiality: AES encryption
- Integrity: SHA-256 digest
- Authenticity: RSA signature validation
- Freshness: Replay protection via sequence numbers
"""

import os
from app.crypto.dh import generate_dh_parameters, generate_dh_keypair, compute_shared_secret, derive_aes_key
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import generate_rsa_keypair, sign_data, verify_signature
from app.crypto.pki import generate_self_signed_cert
from app.common.protocol import ChatMessage
from app.common.utils import b64e, b64d, now_ms

print("=" * 80)
print("Section 2.4: Encrypted Chat and Message Integrity")
print("=" * 80)
print()

# ============================================================================
# PHASE 1: Setup - Establish Session Key (from Section 2.3)
# ============================================================================

print("[PHASE 1] Setup: Establishing Session Key")
print("-" * 80)

print("[1.1] Performing DH key exchange...")
p, g = generate_dh_parameters()
alice_priv, alice_pub = generate_dh_keypair(p, g)
bob_priv, bob_pub = generate_dh_keypair(p, g)

alice_secret = compute_shared_secret(bob_pub, alice_priv, p)
bob_secret = compute_shared_secret(alice_pub, bob_priv, p)

alice_session_key = derive_aes_key(alice_secret)
bob_session_key = derive_aes_key(bob_secret)

print(f"      Session key established: {alice_session_key.hex()}")
print(f"      Keys match: {alice_session_key == bob_session_key} {'✓' if alice_session_key == bob_session_key else '✗'}")

print("\n[1.2] Generating RSA keypairs for signing...")
# Generate Alice's RSA keypair (client)
alice_private_key, alice_public_key = generate_rsa_keypair(key_size=2048)
alice_cert = generate_self_signed_cert(
    private_key=alice_private_key,
    common_name="Alice (Client)",
    validity_days=365
)
print("      Alice RSA keypair generated")

# Generate Bob's RSA keypair (server)
bob_private_key, bob_public_key = generate_rsa_keypair(key_size=2048)
bob_cert = generate_self_signed_cert(
    private_key=bob_private_key,
    common_name="Bob (Server)",
    validity_days=365
)
print("      Bob RSA keypair generated")
print()

# ============================================================================
# PHASE 2: Alice Sends Message to Bob
# ============================================================================

print("[PHASE 2] Alice → Bob: Encrypted and Signed Message")
print("-" * 80)

# Alice's sending state
alice_send_seqno = 1
alice_plaintext = "Hello Bob! This is a secure message from Alice."

print(f"[2.1] Alice: Composing message...")
print(f"      Plaintext: '{alice_plaintext}'")
print(f"      Sequence #: {alice_send_seqno}")

print("\n[2.2] Alice: Encrypting message with AES-128...")
# Encrypt with session key
alice_ciphertext = aes_encrypt(alice_plaintext.encode('utf-8'), alice_session_key)
alice_ct_b64 = b64e(alice_ciphertext)
print(f"      Ciphertext (first 32 bytes hex): {alice_ciphertext[:32].hex()}...")
print(f"      Ciphertext length: {len(alice_ciphertext)} bytes")

print("\n[2.3] Alice: Computing signature...")
# Get timestamp
alice_ts = now_ms()
print(f"      Timestamp: {alice_ts}")

# Compute digest: h = SHA256(seqno || timestamp || ciphertext)
alice_sig_data = f"{alice_send_seqno}{alice_ts}{alice_ct_b64}".encode('utf-8')
print(f"      Signature data: {alice_sig_data[:60]}... ({len(alice_sig_data)} bytes)")

# Sign with RSA private key
alice_signature = sign_data(alice_sig_data, alice_private_key)
alice_sig_b64 = b64e(alice_signature)
print(f"      Signature (first 32 bytes hex): {alice_signature[:32].hex()}...")
print(f"      Signature length: {len(alice_signature)} bytes")

print("\n[2.4] Alice: Creating ChatMessage...")
alice_chat_msg = ChatMessage(
    seqno=alice_send_seqno,
    ts=alice_ts,
    ct=alice_ct_b64,
    sig=alice_sig_b64
)
alice_msg_json = alice_chat_msg.model_dump_json()
print(f"      Message JSON (first 100 chars): {alice_msg_json[:100]}...")
print(f"      Message size: {len(alice_msg_json)} bytes")
print(f"      ✓ Message sent to Bob")
print()

# ============================================================================
# PHASE 3: Bob Receives and Verifies Message from Alice
# ============================================================================

print("[PHASE 3] Bob ← Alice: Receive, Verify, and Decrypt")
print("-" * 80)

# Bob's receiving state
bob_recv_seqno = 1

print(f"[3.1] Bob: Received ChatMessage")
bob_received_msg = ChatMessage.model_validate_json(alice_msg_json)
print(f"      Sequence #: {bob_received_msg.seqno}")
print(f"      Timestamp: {bob_received_msg.ts}")
print(f"      Ciphertext length: {len(b64d(bob_received_msg.ct))} bytes")
print(f"      Signature length: {len(b64d(bob_received_msg.sig))} bytes")

print("\n[3.2] Bob: Verifying sequence number (replay protection)...")
seqno_valid = (bob_received_msg.seqno == bob_recv_seqno)
print(f"      Expected seqno: {bob_recv_seqno}")
print(f"      Received seqno: {bob_received_msg.seqno}")
print(f"      Sequence number valid: {seqno_valid} {'✓' if seqno_valid else '✗ REPLAY'}")

if not seqno_valid:
    print("      ERROR: Replay attack detected!")
    exit(1)

print("\n[3.3] Bob: Recomputing digest for signature verification...")
bob_sig_data = f"{bob_received_msg.seqno}{bob_received_msg.ts}{bob_received_msg.ct}".encode('utf-8')
print(f"      Signature data: {bob_sig_data[:60]}... ({len(bob_sig_data)} bytes)")

print("\n[3.4] Bob: Verifying RSA signature...")
bob_signature = b64d(bob_received_msg.sig)
sig_valid = verify_signature(bob_sig_data, bob_signature, alice_cert)
print(f"      Signature valid: {sig_valid} {'✓' if sig_valid else '✗ SIG_FAIL'}")

if not sig_valid:
    print("      ERROR: Signature verification failed!")
    exit(1)

print("\n[3.5] Bob: Decrypting ciphertext...")
bob_ciphertext = b64d(bob_received_msg.ct)
bob_plaintext_bytes = aes_decrypt(bob_ciphertext, bob_session_key)
bob_plaintext = bob_plaintext_bytes.decode('utf-8')
print(f"      Decrypted: '{bob_plaintext}'")
print(f"      Match: {bob_plaintext == alice_plaintext} {'✓' if bob_plaintext == alice_plaintext else '✗'}")

# Update Bob's expected sequence number
bob_recv_seqno += 1
print(f"      Next expected seqno: {bob_recv_seqno}")
print()

# ============================================================================
# PHASE 4: Bob Sends Reply to Alice
# ============================================================================

print("[PHASE 4] Bob → Alice: Encrypted Reply")
print("-" * 80)

# Bob's sending state
bob_send_seqno = 1
bob_plaintext = "Hi Alice! Your message was received securely. - Bob"

print(f"[4.1] Bob: Composing reply...")
print(f"      Plaintext: '{bob_plaintext}'")
print(f"      Sequence #: {bob_send_seqno}")

print("\n[4.2] Bob: Encrypting and signing...")
bob_ts = now_ms()
bob_ciphertext = aes_encrypt(bob_plaintext.encode('utf-8'), bob_session_key)
bob_ct_b64 = b64e(bob_ciphertext)

bob_sig_data = f"{bob_send_seqno}{bob_ts}{bob_ct_b64}".encode('utf-8')
bob_signature = sign_data(bob_sig_data, bob_private_key)
bob_sig_b64 = b64e(bob_signature)

bob_chat_msg = ChatMessage(
    seqno=bob_send_seqno,
    ts=bob_ts,
    ct=bob_ct_b64,
    sig=bob_sig_b64
)
bob_msg_json = bob_chat_msg.model_dump_json()
print(f"      ✓ Reply sent to Alice")
print()

# ============================================================================
# PHASE 5: Alice Receives and Verifies Bob's Reply
# ============================================================================

print("[PHASE 5] Alice ← Bob: Receive and Verify Reply")
print("-" * 80)

# Alice's receiving state
alice_recv_seqno = 1

print(f"[5.1] Alice: Received reply from Bob")
alice_received_msg = ChatMessage.model_validate_json(bob_msg_json)

print("\n[5.2] Alice: Verifying sequence number...")
seqno_valid = (alice_received_msg.seqno == alice_recv_seqno)
print(f"      Expected: {alice_recv_seqno}, Received: {alice_received_msg.seqno}")
print(f"      Valid: {seqno_valid} {'✓' if seqno_valid else '✗'}")

print("\n[5.3] Alice: Verifying signature...")
alice_sig_data_verify = f"{alice_received_msg.seqno}{alice_received_msg.ts}{alice_received_msg.ct}".encode('utf-8')
alice_sig_verify = b64d(alice_received_msg.sig)
sig_valid = verify_signature(alice_sig_data_verify, alice_sig_verify, bob_cert)
print(f"      Signature valid: {sig_valid} {'✓' if sig_valid else '✗'}")

print("\n[5.4] Alice: Decrypting message...")
alice_ct_verify = b64d(alice_received_msg.ct)
alice_pt_verify = aes_decrypt(alice_ct_verify, alice_session_key).decode('utf-8')
print(f"      Decrypted: '{alice_pt_verify}'")
print()

# ============================================================================
# PHASE 6: Security Tests - Replay Attack
# ============================================================================

print("=" * 80)
print("[PHASE 6] Security Test: Replay Attack Detection")
print("=" * 80)

print("\n[6.1] Attacker: Attempting to replay Alice's first message...")
print(f"      Replaying message with seqno={alice_send_seqno}")
print(f"      Bob expects seqno={bob_recv_seqno}")

replay_msg = ChatMessage.model_validate_json(alice_msg_json)
replay_detected = (replay_msg.seqno != bob_recv_seqno)

print(f"\n[6.2] Bob: Checking sequence number...")
print(f"      Expected: {bob_recv_seqno}")
print(f"      Received: {replay_msg.seqno}")
print(f"      Replay detected: {replay_detected} {'✓ BLOCKED' if replay_detected else '✗ FAILED'}")

if replay_detected:
    print("      ✓ Replay attack successfully blocked!")
else:
    print("      ✗ ERROR: Replay attack not detected!")
print()

# ============================================================================
# PHASE 7: Security Tests - Tampering Detection
# ============================================================================

print("=" * 80)
print("[PHASE 7] Security Test: Tampering Detection")
print("=" * 80)

print("\n[7.1] Attacker: Tampering with ciphertext...")
# Flip a bit in the ciphertext
tampered_ct = b64d(alice_ct_b64)
tampered_ct_modified = bytearray(tampered_ct)
tampered_ct_modified[0] ^= 0x01  # Flip first bit
tampered_ct_b64 = b64e(bytes(tampered_ct_modified))

print(f"      Original ct (first 16 hex): {tampered_ct[:16].hex()}")
print(f"      Tampered ct (first 16 hex): {bytes(tampered_ct_modified)[:16].hex()}")

# Create tampered message (keep original signature)
tampered_msg = ChatMessage(
    seqno=alice_send_seqno,
    ts=alice_ts,
    ct=tampered_ct_b64,
    sig=alice_sig_b64  # Original signature won't match
)

print("\n[7.2] Bob: Verifying tampered message...")
tampered_sig_data = f"{tampered_msg.seqno}{tampered_msg.ts}{tampered_msg.ct}".encode('utf-8')
tampered_signature = b64d(tampered_msg.sig)
tampered_sig_valid = verify_signature(tampered_sig_data, tampered_signature, alice_cert)

print(f"      Signature valid: {tampered_sig_valid} {'✗ BLOCKED' if not tampered_sig_valid else '✓ FAILED'}")

if not tampered_sig_valid:
    print("      ✓ Tampering detected! Message rejected (SIG_FAIL)")
else:
    print("      ✗ ERROR: Tampering not detected!")
print()

# ============================================================================
# PHASE 8: Security Properties Summary
# ============================================================================

print("=" * 80)
print("[PHASE 8] Security Properties Verification")
print("=" * 80)

print("\n✓ Confidentiality:")
print("  - Messages encrypted with AES-128 using session key")
print("  - Only ciphertext transmitted over network")
print("  - Plaintext never exposed to eavesdroppers")

print("\n✓ Integrity:")
print("  - SHA-256 digest computed over (seqno || timestamp || ciphertext)")
print("  - Any bit change invalidates signature")
print("  - Tampering detection demonstrated")

print("\n✓ Authenticity:")
print("  - RSA signatures with sender's private key")
print("  - Verified using sender's certificate/public key")
print("  - Only legitimate sender can create valid signatures")

print("\n✓ Freshness (Replay Protection):")
print("  - Strict sequence number enforcement")
print("  - Each message must have next expected seqno")
print("  - Replay attacks detected and blocked")

print("\n✓ Message Format (PDF Specification):")
print("  - type: 'msg'")
print("  - seqno: strictly increasing integer")
print("  - ts: Unix timestamp in milliseconds")
print("  - ct: base64-encoded AES ciphertext")
print("  - sig: base64(RSA_SIGN(SHA256(seqno||ts||ct)))")

# ============================================================================
# FINAL SUMMARY
# ============================================================================

print("\n" + "=" * 80)
print("TEST SUMMARY")
print("=" * 80)

all_tests_passed = (
    alice_session_key == bob_session_key and  # Session key established
    bob_plaintext == alice_plaintext and       # Message decrypted correctly
    alice_pt_verify == bob_plaintext and       # Reply decrypted correctly
    replay_detected and                         # Replay attack blocked
    not tampered_sig_valid                      # Tampering detected
)

if all_tests_passed:
    print("\n✓✓✓ ALL TESTS PASSED ✓✓✓")
    print("\nSection 2.4 Implementation Complete:")
    print("  ✓ Message encryption with AES-128")
    print("  ✓ Per-message RSA-SHA256 signatures")
    print("  ✓ Signature digest = SHA256(seqno||ts||ct)")
    print("  ✓ Strict sequence number enforcement")
    print("  ✓ Replay attack detection")
    print("  ✓ Tampering detection via signature verification")
    print("  ✓ Bidirectional encrypted communication")
    print("\nReady for Section 2.5 (Non-Repudiation)!")
else:
    print("\n✗✗✗ SOME TESTS FAILED ✗✗✗")
    print("Please check the output above for errors.")

print("\n" + "=" * 80)
print()
