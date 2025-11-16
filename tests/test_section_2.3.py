"""
Integration Test for Section 2.3: Session Key Establishment

This test demonstrates the Diffie-Hellman key exchange that occurs AFTER
successful login to establish a chat session key for encrypted messaging.

Protocol Flow:
1. Client generates DH parameters (p, g) and keypair (a, A)
2. Client sends DHClientMessage with {p, g, A}
3. Server receives, generates keypair (b, B)
4. Server computes shared secret Ks = A^b mod p
5. Server sends DHServerMessage with {B}
6. Client receives B, computes shared secret Ks = B^a mod p
7. Both derive session key: K = Trunc16(SHA256(big-endian(Ks)))
8. Session key K is used for AES-128 chat encryption

This is Section 2.3 - DIFFERENT from Section 2.2 (registration/login crypto)
"""

import json
from app.crypto.dh import (
    generate_dh_parameters,
    generate_dh_keypair,
    compute_shared_secret,
    derive_aes_key
)
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.common.protocol import DHClientMessage, DHServerMessage, ChatMessage
from app.common.utils import b64e, b64d, now_ms, sha256_bytes
from app.crypto.sign import load_private_key, sign_data, verify_signature, load_certificate


print("=" * 80)
print("Section 2.3: Session Key Establishment (Post-Login DH)")
print("=" * 80)
print()

# ============================================================================
# PHASE 1: Client Initiates DH Exchange
# ============================================================================

print("[PHASE 1] Client: Initiating DH Key Exchange")
print("-" * 80)

# Step 1: Generate DH parameters (p, g)
print("[1.1] Client: Generating DH parameters...")
p, g = generate_dh_parameters()
print(f"      Prime p: {p.bit_length()} bits")
print(f"      Generator g: {g}")

# Step 2: Generate client DH keypair
print("\n[1.2] Client: Generating DH keypair...")
client_private_key, client_public_key = generate_dh_keypair(p, g)
print(f"      Client private key: {client_private_key.bit_length()} bits (kept secret)")
print(f"      Client public A: {client_public_key.bit_length()} bits")
print(f"      A = g^a mod p (first 64 hex): {hex(client_public_key)[:66]}...")

# Step 3: Create DHClientMessage
print("\n[1.3] Client: Creating DHClientMessage...")
dh_client_msg = DHClientMessage(
    p=p,
    g=g,
    A=client_public_key
)
print(f"      Message type: {dh_client_msg.type}")
print(f"      Sending (p, g, A) to server...")

# Simulate message transmission
dh_client_json = dh_client_msg.model_dump_json()
print(f"      JSON size: {len(dh_client_json)} bytes")
print()

# ============================================================================
# PHASE 2: Server Responds with DH
# ============================================================================

print("[PHASE 2] Server: Processing DH Request and Responding")
print("-" * 80)

# Step 1: Server receives DHClientMessage
print("[2.1] Server: Received DHClientMessage")
received_dh_client = DHClientMessage.model_validate_json(dh_client_json)
print(f"      Extracted p: {received_dh_client.p.bit_length()} bits")
print(f"      Extracted g: {received_dh_client.g}")
print(f"      Extracted A: {received_dh_client.A.bit_length()} bits")

# Step 2: Server generates its own DH keypair
print("\n[2.2] Server: Generating DH keypair...")
server_private_key, server_public_key = generate_dh_keypair(
    received_dh_client.p,
    received_dh_client.g
)
print(f"      Server private key: {server_private_key.bit_length()} bits (kept secret)")
print(f"      Server public B: {server_public_key.bit_length()} bits")
print(f"      B = g^b mod p (first 64 hex): {hex(server_public_key)[:66]}...")

# Step 3: Server computes shared secret
print("\n[2.3] Server: Computing shared secret...")
server_shared_secret = compute_shared_secret(
    peer_public_key=received_dh_client.A,
    private_key=server_private_key,
    p=received_dh_client.p
)
print(f"      Ks = A^b mod p")
print(f"      Shared secret (first 64 hex): {hex(server_shared_secret)[:66]}...")
print(f"      Shared secret: {server_shared_secret.bit_length()} bits")

# Step 4: Server derives AES-128 key
print("\n[2.4] Server: Deriving AES-128 session key...")
server_session_key = derive_aes_key(server_shared_secret)
print(f"      K = Trunc16(SHA256(big-endian(Ks)))")
print(f"      Session key: {server_session_key.hex()}")
print(f"      Key length: {len(server_session_key)} bytes (AES-128)")

# Step 5: Server sends DHServerMessage
print("\n[2.5] Server: Creating DHServerMessage...")
dh_server_msg = DHServerMessage(B=server_public_key)
print(f"      Message type: {dh_server_msg.type}")
print(f"      Sending B to client...")

dh_server_json = dh_server_msg.model_dump_json()
print(f"      JSON size: {len(dh_server_json)} bytes")
print()

# ============================================================================
# PHASE 3: Client Completes DH Exchange
# ============================================================================

print("[PHASE 3] Client: Completing DH Exchange")
print("-" * 80)

# Step 1: Client receives DHServerMessage
print("[3.1] Client: Received DHServerMessage")
received_dh_server = DHServerMessage.model_validate_json(dh_server_json)
print(f"      Extracted B: {received_dh_server.B.bit_length()} bits")

# Step 2: Client computes shared secret
print("\n[3.2] Client: Computing shared secret...")
client_shared_secret = compute_shared_secret(
    peer_public_key=received_dh_server.B,
    private_key=client_private_key,
    p=p
)
print(f"      Ks = B^a mod p")
print(f"      Shared secret (first 64 hex): {hex(client_shared_secret)[:66]}...")
print(f"      Shared secret: {client_shared_secret.bit_length()} bits")

# Step 3: Client derives AES-128 key
print("\n[3.3] Client: Deriving AES-128 session key...")
client_session_key = derive_aes_key(client_shared_secret)
print(f"      K = Trunc16(SHA256(big-endian(Ks)))")
print(f"      Session key: {client_session_key.hex()}")
print(f"      Key length: {len(client_session_key)} bytes (AES-128)")

# ============================================================================
# PHASE 4: Verification
# ============================================================================

print("\n" + "=" * 80)
print("[PHASE 4] Verification: DH Key Exchange Success")
print("=" * 80)

print("\n[4.1] Verifying shared secrets match...")
secrets_match = client_shared_secret == server_shared_secret
print(f"      Client Ks: {hex(client_shared_secret)[:66]}...")
print(f"      Server Ks: {hex(server_shared_secret)[:66]}...")
print(f"      Secrets match: {secrets_match} {'✓' if secrets_match else '✗'}")

print("\n[4.2] Verifying session keys match...")
keys_match = client_session_key == server_session_key
print(f"      Client K: {client_session_key.hex()}")
print(f"      Server K: {server_session_key.hex()}")
print(f"      Keys match: {keys_match} {'✓' if keys_match else '✗'}")

print("\n[4.3] Verifying key properties...")
print(f"      Key length correct (16 bytes): {len(client_session_key) == 16} {'✓' if len(client_session_key) == 16 else '✗'}")
print(f"      Key is non-zero: {client_session_key != b'\\x00' * 16} {'✓' if client_session_key != b'\\x00' * 16 else '✗'}")

# ============================================================================
# PHASE 5: Demonstrate Session Key Usage for Chat
# ============================================================================

print("\n" + "=" * 80)
print("[PHASE 5] Demonstration: Using Session Key for Encrypted Chat")
print("=" * 80)

print("\n[5.1] Client: Encrypting chat message...")
plaintext_message = "Hello, this is a secure chat message! Module 2.3 working!"
print(f"      Plaintext: '{plaintext_message}'")

# Encrypt with session key
ciphertext = aes_encrypt(plaintext_message.encode('utf-8'), client_session_key)
print(f"      Ciphertext (hex): {ciphertext.hex()}")
print(f"      Ciphertext length: {len(ciphertext)} bytes")

print("\n[5.2] Server: Decrypting chat message...")
# Decrypt with session key
decrypted_message = aes_decrypt(ciphertext, server_session_key)
print(f"      Decrypted: '{decrypted_message.decode('utf-8')}'")
print(f"      Match: {decrypted_message.decode('utf-8') == plaintext_message} {'✓' if decrypted_message.decode('utf-8') == plaintext_message else '✗'}")

print("\n[5.3] Creating ChatMessage with signature...")
# Load client private key for signing
try:
    client_priv_key = load_private_key('certs/client_key.pem')

    seqno = 1
    ts = now_ms()
    ct_b64 = b64e(ciphertext)

    # Create signature: RSA-sign(SHA256(seqno||ts||ct))
    sig_data = f"{seqno}{ts}{ct_b64}".encode('utf-8')
    signature = sign_data(sig_data, client_priv_key)

    chat_msg = ChatMessage(
        seqno=seqno,
        ts=ts,
        ct=ct_b64,
        sig=b64e(signature)
    )

    print(f"      Message created:")
    print(f"      - Sequence: {chat_msg.seqno}")
    print(f"      - Timestamp: {chat_msg.ts}")
    print(f"      - Ciphertext (first 32 chars): {chat_msg.ct[:32]}...")
    print(f"      - Signature (first 32 chars): {chat_msg.sig[:32]}...")

    # Verify signature
    client_cert = load_certificate('certs/client_cert.pem')
    sig_verify_data = f"{chat_msg.seqno}{chat_msg.ts}{chat_msg.ct}".encode('utf-8')
    sig_valid = verify_signature(sig_verify_data, b64d(chat_msg.sig), client_cert)
    print(f"      - Signature valid: {sig_valid} {'✓' if sig_valid else '✗'}")

except FileNotFoundError:
    print("      [NOTE] Client certificate not found - skipping signature demo")
    print("      Run 'python scripts/gen_cert.py --cn client.local --out certs/client' first")

# ============================================================================
# PHASE 6: Security Properties Summary
# ============================================================================

print("\n" + "=" * 80)
print("[PHASE 6] Security Properties Achieved")
print("=" * 80)

print("\n✓ Confidentiality:")
print("  - Session key derived from DH shared secret")
print("  - Only client and server can compute Ks = A^b = B^a mod p")
print("  - AES-128 encryption with derived key K")
print("  - Different sessions will have different keys (forward separation)")

print("\n✓ Key Derivation:")
print("  - K = Trunc16(SHA256(big-endian(Ks)))")
print("  - Derives 16-byte key from large DH shared secret")
print("  - One-way function prevents Ks recovery from K")

print("\n✓ Post-Authentication:")
print("  - DH exchange happens AFTER successful login")
print("  - Separate from registration/login credential protection")
print("  - Fresh session key for each chat session")

print("\n✓ No Key Transmission:")
print("  - Session key K never transmitted over network")
print("  - Only public values (p, g, A, B) sent")
print("  - Private keys (a, b) never leave their respective systems")

# ============================================================================
# FINAL SUMMARY
# ============================================================================

print("\n" + "=" * 80)
print("TEST SUMMARY")
print("=" * 80)

all_tests_passed = (
    secrets_match and
    keys_match and
    len(client_session_key) == 16 and
    plaintext_message == decrypted_message.decode('utf-8')
)

if all_tests_passed:
    print("\n✓✓✓ ALL TESTS PASSED ✓✓✓")
    print("\nSection 2.3 Implementation Complete:")
    print("  ✓ DH key exchange successful")
    print("  ✓ Shared secrets match")
    print("  ✓ Session keys match")
    print("  ✓ Key length correct (16 bytes for AES-128)")
    print("  ✓ Encryption/decryption working")
    print("\nReady for chat message exchange (Section 2.4)!")
else:
    print("\n✗✗✗ SOME TESTS FAILED ✗✗✗")
    print("Please check the output above for errors.")

print("\n" + "=" * 80)
print()
