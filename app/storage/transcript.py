"""
Append-only transcript + TranscriptHash helpers.

Section 2.5: Non-Repudiation and Session Closure

This module implements the transcript logging and SessionReceipt generation
required for non-repudiation (PDF Page 5, 9).

Transcript Format (per PDF specification):
    seqno | timestamp | ciphertext | signature | peer-cert-fingerprint

TranscriptHash Computation:
    TranscriptHash = SHA256(concatenation of all log lines)

SessionReceipt Format:
    {
        "type": "receipt",
        "peer": "client|server",
        "first_seq": int,
        "last_seq": int,
        "transcript_sha256": hex_string,
        "sig": base64(RSA_SIGN(transcript_sha256))
    }

Security Properties:
    - Non-Repudiation: Signed receipt proves participation
    - Tamper-Evidence: Hash ensures transcript integrity
    - Verifiable Proof: Third parties can verify offline
"""

import os
from typing import Optional, Tuple
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from app.common.utils import sha256_bytes, b64e, b64d
from app.crypto.sign import sign_data, verify_signature
from app.common.protocol import SessionReceiptMessage


class TranscriptManager:
    """
    Manages append-only transcript file for a chat session.

    Each message is logged with: seqno | ts | ct | sig | peer-cert-fingerprint
    At session end, computes TranscriptHash and generates signed SessionReceipt.
    """

    def __init__(self, transcript_path: str, peer_cert: x509.Certificate):
        """
        Initialize transcript manager.

        Args:
            transcript_path: Path to append-only transcript file
            peer_cert: Peer's X.509 certificate for fingerprint
        """
        self.transcript_path = transcript_path
        self.peer_cert = peer_cert
        self.peer_fingerprint = self._compute_cert_fingerprint(peer_cert)

        # Track sequence numbers
        self.first_seq: Optional[int] = None
        self.last_seq: Optional[int] = None

        # Ensure transcript directory exists
        os.makedirs(os.path.dirname(transcript_path), exist_ok=True)

        # Initialize empty transcript file (append mode)
        if not os.path.exists(transcript_path):
            with open(transcript_path, 'w') as f:
                pass  # Create empty file

    def _compute_cert_fingerprint(self, cert: x509.Certificate) -> str:
        """
        Compute SHA-256 fingerprint of certificate.

        Args:
            cert: X.509 certificate

        Returns:
            Hex-encoded SHA-256 fingerprint
        """
        cert_bytes = cert.public_bytes(encoding=x509.Encoding.DER)
        fingerprint_bytes = sha256_bytes(cert_bytes)
        return fingerprint_bytes.hex()

    def append_message(self, seqno: int, ts: int, ct: str, sig: str) -> None:
        """
        Append a message to the transcript (append-only).

        PDF Specification (Page 5, 9):
        Format: seqno | timestamp | ciphertext | signature | peer-cert-fingerprint

        Args:
            seqno: Sequence number
            ts: Unix timestamp in milliseconds
            ct: Base64-encoded ciphertext
            sig: Base64-encoded RSA signature
        """
        # Update sequence number tracking
        if self.first_seq is None:
            self.first_seq = seqno
        self.last_seq = seqno

        # Construct log line per PDF specification
        log_line = f"{seqno}|{ts}|{ct}|{sig}|{self.peer_fingerprint}\n"

        # Append to file (append-only)
        with open(self.transcript_path, 'a') as f:
            f.write(log_line)

    def compute_transcript_hash(self) -> str:
        """
        Compute SHA-256 hash of entire transcript.

        PDF Specification (Page 5, 9):
        TranscriptHash = SHA256(concatenation of all log lines)

        Returns:
            Hex-encoded SHA-256 hash of transcript
        """
        # Read entire transcript
        with open(self.transcript_path, 'r') as f:
            transcript_content = f.read()

        # Compute SHA-256 hash
        transcript_bytes = transcript_content.encode('utf-8')
        hash_bytes = sha256_bytes(transcript_bytes)

        return hash_bytes.hex()

    def generate_session_receipt(
        self,
        peer: str,
        private_key
    ) -> SessionReceiptMessage:
        """
        Generate a signed SessionReceipt for non-repudiation.

        PDF Specification (Page 5, 9):
        {
            "type": "receipt",
            "peer": "client|server",
            "first_seq": int,
            "last_seq": int,
            "transcript_sha256": hex_string,
            "sig": base64(RSA_SIGN(transcript_sha256))
        }

        Args:
            peer: "client" or "server"
            private_key: RSA private key for signing

        Returns:
            SessionReceiptMessage with signed transcript hash
        """
        # Compute transcript hash
        transcript_hash = self.compute_transcript_hash()

        # Sign the transcript hash with RSA private key
        transcript_hash_bytes = bytes.fromhex(transcript_hash)
        signature = sign_data(transcript_hash_bytes, private_key)
        sig_b64 = b64e(signature)

        # Create SessionReceipt
        receipt = SessionReceiptMessage(
            peer=peer,
            first_seq=self.first_seq if self.first_seq is not None else 0,
            last_seq=self.last_seq if self.last_seq is not None else 0,
            transcript_sha256=transcript_hash,
            sig=sig_b64
        )

        return receipt

    def save_receipt(self, receipt: SessionReceiptMessage, receipt_path: str) -> None:
        """
        Save SessionReceipt to file for offline verification.

        Args:
            receipt: SessionReceiptMessage to save
            receipt_path: Path to save receipt JSON
        """
        # Ensure directory exists
        os.makedirs(os.path.dirname(receipt_path), exist_ok=True)

        # Save as JSON
        with open(receipt_path, 'w') as f:
            f.write(receipt.model_dump_json(indent=2))


def verify_session_receipt(
    transcript_path: str,
    receipt: SessionReceiptMessage,
    signer_cert: x509.Certificate
) -> bool:
    """
    Offline verification of SessionReceipt.

    PDF Specification (Page 9-10):
    Offline verification must confirm that any transcript modification
    invalidates the receipt signature.

    Verification Process:
    1. Recompute TranscriptHash from transcript file
    2. Verify that recomputed hash matches receipt.transcript_sha256
    3. Verify RSA signature using signer's certificate

    Args:
        transcript_path: Path to transcript file
        receipt: SessionReceiptMessage to verify
        signer_cert: X.509 certificate of signer

    Returns:
        True if receipt is valid, False otherwise
    """
    # Step 1: Recompute transcript hash
    with open(transcript_path, 'r') as f:
        transcript_content = f.read()

    transcript_bytes = transcript_content.encode('utf-8')
    recomputed_hash_bytes = sha256_bytes(transcript_bytes)
    recomputed_hash = recomputed_hash_bytes.hex()

    # Step 2: Verify hash matches
    if recomputed_hash != receipt.transcript_sha256:
        return False

    # Step 3: Verify RSA signature
    signature = b64d(receipt.sig)
    transcript_hash_bytes = bytes.fromhex(receipt.transcript_sha256)

    sig_valid = verify_signature(transcript_hash_bytes, signature, signer_cert)

    return sig_valid


def verify_message_in_transcript(
    transcript_line: str,
    sender_cert: x509.Certificate
) -> bool:
    """
    Verify a single message line from the transcript.

    This allows verification that each individual message in the transcript
    has a valid signature.

    Args:
        transcript_line: Single line from transcript (seqno|ts|ct|sig|fingerprint)
        sender_cert: X.509 certificate of message sender

    Returns:
        True if message signature is valid, False otherwise
    """
    # Parse transcript line
    parts = transcript_line.strip().split('|')
    if len(parts) != 5:
        return False

    seqno, ts, ct, sig_b64, fingerprint = parts

    # Recompute signature data (must match send/receive functions)
    # Format: SHA256(seqno || ts || ct)
    sig_data = f"{seqno}{ts}{ct}".encode('utf-8')

    # Verify signature
    signature = b64d(sig_b64)
    sig_valid = verify_signature(sig_data, signature, sender_cert)

    return sig_valid


# Example usage and testing
if __name__ == "__main__":
    print("=" * 80)
    print("Transcript and SessionReceipt Module Test")
    print("=" * 80)
    print()

    from app.crypto.sign import generate_rsa_keypair
    from app.crypto.pki import generate_self_signed_cert
    from app.common.utils import now_ms

    # Setup test certificates
    print("[1] Generating test certificates...")
    alice_priv, alice_pub = generate_rsa_keypair(2048)
    alice_cert = generate_self_signed_cert(alice_priv, "Alice", 365)

    bob_priv, bob_pub = generate_rsa_keypair(2048)
    bob_cert = generate_self_signed_cert(bob_priv, "Bob", 365)
    print("    Certificates generated")

    # Create transcript manager
    print("\n[2] Creating transcript manager...")
    transcript_path = "test_transcript.log"
    manager = TranscriptManager(transcript_path, alice_cert)
    print(f"    Transcript: {transcript_path}")
    print(f"    Peer fingerprint: {manager.peer_fingerprint[:16]}...")

    # Append some test messages
    print("\n[3] Appending test messages...")
    for i in range(1, 4):
        seqno = i
        ts = now_ms()
        ct = b64e(f"ciphertext_{i}".encode())

        # Sign the message
        sig_data = f"{seqno}{ts}{ct}".encode('utf-8')
        sig = sign_data(sig_data, bob_priv)
        sig_b64 = b64e(sig)

        manager.append_message(seqno, ts, ct, sig_b64)
        print(f"    Message {i} appended")

    # Compute transcript hash
    print("\n[4] Computing transcript hash...")
    transcript_hash = manager.compute_transcript_hash()
    print(f"    TranscriptHash: {transcript_hash}")

    # Generate session receipt
    print("\n[5] Generating SessionReceipt...")
    receipt = manager.generate_session_receipt("server", bob_priv)
    print(f"    Receipt peer: {receipt.peer}")
    print(f"    Receipt range: seq {receipt.first_seq} to {receipt.last_seq}")
    print(f"    Receipt hash: {receipt.transcript_sha256[:32]}...")
    print(f"    Receipt sig: {receipt.sig[:32]}...")

    # Save receipt
    receipt_path = "test_receipt.json"
    manager.save_receipt(receipt, receipt_path)
    print(f"    Receipt saved to: {receipt_path}")

    # Verify receipt (offline)
    print("\n[6] Verifying SessionReceipt (offline)...")
    is_valid = verify_session_receipt(transcript_path, receipt, bob_cert)
    print(f"    Receipt valid: {is_valid} {'✓' if is_valid else '✗'}")

    # Test tampering detection
    print("\n[7] Testing tampering detection...")
    print("    Modifying transcript file...")
    with open(transcript_path, 'a') as f:
        f.write("999|123456|tampered|fake_sig|fake_fingerprint\n")

    tampered_valid = verify_session_receipt(transcript_path, receipt, bob_cert)
    print(f"    Tampered receipt valid: {tampered_valid} {'✗ FAILED' if tampered_valid else '✓ DETECTED'}")

    # Cleanup
    print("\n[8] Cleanup...")
    os.remove(transcript_path)
    os.remove(receipt_path)
    print("    Test files removed")

    print("\n" + "=" * 80)
    if is_valid and not tampered_valid:
        print("✓✓✓ ALL TESTS PASSED ✓✓✓")
    else:
        print("✗✗✗ SOME TESTS FAILED ✗✗✗")
    print("=" * 80)
    print()
