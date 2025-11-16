"""Client skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import json
from typing import Optional
from app.common.protocol import (
    HelloMessage, ServerHelloMessage, DHClientMessage, DHServerMessage,
    RegisterMessage, LoginMessage, AuthResponseMessage, ChatMessage,
    SessionReceiptMessage, ErrorMessage
)
from app.crypto.pki import load_certificate, validate_certificate, load_private_key
from app.crypto.dh import generate_dh_parameters, generate_dh_keypair, compute_shared_secret, derive_aes_key
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import sign_data, verify_signature
from app.common.utils import b64e, b64d, generate_nonce, now_ms


def send_message(sock: socket.socket, msg):
    """Send a JSON message over the socket."""
    json_data = msg.model_dump_json()
    sock.sendall(json_data.encode('utf-8') + b'\n')


def receive_message(sock: socket.socket) -> dict:
    """Receive a JSON message from the socket."""
    buffer = b''
    while b'\n' not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed by server")
        buffer += chunk

    # Split at first newline
    msg_data, _ = buffer.split(b'\n', 1)
    return json.loads(msg_data.decode('utf-8'))


def client_session_key_establishment(sock: socket.socket) -> bytes:
    """
    Section 2.3: Post-Login Session Key Establishment

    After successful login, perform DH key exchange to establish a chat session key.

    Client Flow:
    1. Generate DH parameters (p, g)
    2. Generate client DH keypair (a, A) where A = g^a mod p
    3. Send DHClientMessage with {p, g, A}
    4. Receive DHServerMessage with {B}
    5. Compute shared secret Ks = B^a mod p
    6. Derive session key K = Trunc16(SHA256(big-endian(Ks)))

    Args:
        sock: Connected socket to server

    Returns:
        16-byte AES-128 session key
    """
    print("\n[CLIENT] Starting Session Key Establishment (Section 2.3)...")

    # Step 1: Generate DH parameters
    print("[CLIENT] Generating DH parameters...")
    p, g = generate_dh_parameters()

    # Step 2: Generate client DH keypair
    print("[CLIENT] Generating DH keypair...")
    client_private_key, client_public_key = generate_dh_keypair(p, g)
    print(f"[CLIENT] Public key A: {client_public_key.bit_length()} bits")

    # Step 3: Send DHClientMessage
    print("[CLIENT] Sending DHClientMessage to server...")
    dh_client_msg = DHClientMessage(p=p, g=g, A=client_public_key)
    send_message(sock, dh_client_msg)

    # Step 4: Receive DHServerMessage
    print("[CLIENT] Waiting for DHServerMessage from server...")
    response = receive_message(sock)
    dh_server_msg = DHServerMessage.model_validate(response)
    print(f"[CLIENT] Received server public key B: {dh_server_msg.B.bit_length()} bits")

    # Step 5: Compute shared secret
    print("[CLIENT] Computing shared secret...")
    shared_secret = compute_shared_secret(
        peer_public_key=dh_server_msg.B,
        private_key=client_private_key,
        p=p
    )

    # Step 6: Derive session key
    print("[CLIENT] Deriving AES-128 session key...")
    session_key = derive_aes_key(shared_secret)
    print(f"[CLIENT] Session key established: {session_key.hex()}")
    print("[CLIENT] ✓ Session Key Establishment complete!")

    return session_key


def send_chat_message(
    sock: socket.socket,
    plaintext: str,
    session_key: bytes,
    seqno: int,
    private_key,
    transcript_manager=None
) -> None:
    """
    Section 2.4: Send an encrypted and signed chat message.

    Message Transmission Process (PDF Page 4-5, Section 1.3):
    1. Pad plaintext (PKCS#7) and encrypt with AES-128 using session_key
    2. Compute digest: h = SHA256(seqno || timestamp || ciphertext)
    3. Sign digest with sender's RSA private key
    4. Send as ChatMessage
    5. Log to transcript (Section 2.5)

    Args:
        sock: Connected socket
        plaintext: Message to send
        session_key: 16-byte AES-128 key from DH exchange
        seqno: Sequence number (strictly increasing)
        private_key: Sender's RSA private key for signing
        transcript_manager: Optional TranscriptManager for logging (Section 2.5)

    Raises:
        ConnectionError: If send fails
    """
    # Step 1: Get timestamp
    ts = now_ms()

    # Step 2: Encrypt plaintext with AES-128
    ciphertext = aes_encrypt(plaintext.encode('utf-8'), session_key)
    ct_b64 = b64e(ciphertext)

    # Step 3: Compute SHA-256 digest over seqno || timestamp || ciphertext
    # CRITICAL: Concatenation format matches PDF specification
    sig_data = f"{seqno}{ts}{ct_b64}".encode('utf-8')

    # Step 4: Sign the digest with RSA private key
    signature = sign_data(sig_data, private_key)
    sig_b64 = b64e(signature)

    # Step 5: Create and send ChatMessage
    chat_msg = ChatMessage(
        seqno=seqno,
        ts=ts,
        ct=ct_b64,
        sig=sig_b64
    )

    send_message(sock, chat_msg)
    print(f"[CLIENT] Sent message #{seqno}: '{plaintext}' (encrypted)")

    # Step 6: Log to transcript (Section 2.5)
    if transcript_manager is not None:
        transcript_manager.append_message(seqno, ts, ct_b64, sig_b64)


def receive_chat_message(
    sock: socket.socket,
    session_key: bytes,
    expected_seqno: int,
    peer_cert,
    transcript_manager=None
) -> tuple[str, int]:
    """
    Section 2.4: Receive, verify, and decrypt a chat message.

    Recipient Verification Process (PDF Page 4, Section 1.3):
    1. Check seqno is strictly increasing (replay protection)
    2. Verify signature using sender's certificate and recomputed hash
    3. Decrypt ciphertext with AES-128 and remove PKCS#7 padding
    4. Log to transcript (Section 2.5)

    Args:
        sock: Connected socket
        session_key: 16-byte AES-128 key from DH exchange
        expected_seqno: Expected sequence number (for replay protection)
        peer_cert: Sender's X.509 certificate for signature verification
        transcript_manager: Optional TranscriptManager for logging (Section 2.5)

    Returns:
        Tuple of (plaintext_message, next_expected_seqno)

    Raises:
        ValueError: With "REPLAY" if seqno doesn't match expected
        ValueError: With "SIG_FAIL" if signature verification fails
        ValueError: If decryption fails (padding error)
    """
    # Step 1: Receive ChatMessage
    response = receive_message(sock)
    chat_msg = ChatMessage.model_validate(response)

    # Step 2: Verify sequence number (replay protection)
    if chat_msg.seqno != expected_seqno:
        raise ValueError(
            f"REPLAY: Expected seqno {expected_seqno}, got {chat_msg.seqno}"
        )

    # Step 3: Recompute digest for signature verification
    sig_data = f"{chat_msg.seqno}{chat_msg.ts}{chat_msg.ct}".encode('utf-8')

    # Step 4: Verify RSA signature
    signature = b64d(chat_msg.sig)
    sig_valid = verify_signature(sig_data, signature, peer_cert)

    if not sig_valid:
        raise ValueError("SIG_FAIL: Message signature verification failed")

    # Step 5: Decrypt ciphertext
    ciphertext = b64d(chat_msg.ct)
    try:
        plaintext_bytes = aes_decrypt(ciphertext, session_key)
        plaintext = plaintext_bytes.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

    print(f"[CLIENT] Received message #{chat_msg.seqno}: '{plaintext}' (decrypted)")

    # Step 6: Log to transcript (Section 2.5)
    if transcript_manager is not None:
        transcript_manager.append_message(chat_msg.seqno, chat_msg.ts, chat_msg.ct, chat_msg.sig)

    # Return plaintext and next expected sequence number
    return plaintext, expected_seqno + 1


def main():
    """
    Main client workflow.

    Protocol Flow:
    1. PKI Connect (Section 2.1)
    2. Certificate Verification (Section 2.1)
    3. Registration or Login (Section 2.2)
    4. Session Key Establishment (Section 2.3) <- IMPLEMENTED
    5. Encrypted Chat (Section 2.4) <- IMPLEMENTED
    6. Session Receipt (Section 2.5)
    """
    print("=" * 80)
    print("SecureChat Client")
    print("=" * 80)

    # TODO: Implement full client workflow
    # For now, this is a skeleton showing where functions fit

    print("\n[INFO] Client workflow not fully implemented yet.")
    print("[INFO] Available functions:")
    print("       Section 2.3: client_session_key_establishment(sock)")
    print("       Section 2.4: send_chat_message(sock, plaintext, session_key, seqno, private_key)")
    print("       Section 2.4: receive_chat_message(sock, session_key, expected_seqno, peer_cert)")
    print("\n[INFO] To test Section 2.4, run: python tests/test_section_2.4.py")

    # Example of complete workflow:
    # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sock.connect(('localhost', 5000))
    # ... PKI handshake ...
    # ... Registration/Login ...
    # session_key = client_session_key_establishment(sock)  # Section 2.3
    #
    # # Chat loop (Section 2.4)
    # client_private_key = load_private_key('certs/client_key.pem')
    # server_cert = load_certificate('certs/server_cert.pem')
    # send_seqno = 1
    # recv_seqno = 1
    #
    # while True:
    #     user_input = input("You: ")
    #     send_chat_message(sock, user_input, session_key, send_seqno, client_private_key)
    #     send_seqno += 1
    #
    #     reply, recv_seqno = receive_chat_message(sock, session_key, recv_seqno, server_cert)
    #     print(f"Server: {reply}")


if __name__ == "__main__":
    main()
