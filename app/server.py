"""Server skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import json
from typing import Optional
from app.common.protocol import (
    HelloMessage, ServerHelloMessage, DHClientMessage, DHServerMessage,
    RegisterMessage, LoginMessage, AuthResponseMessage, ChatMessage,
    SessionReceiptMessage, ErrorMessage
)
from app.crypto.pki import load_certificate, validate_certificate, load_private_key
from app.crypto.dh import generate_dh_keypair, compute_shared_secret, derive_aes_key
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
            raise ConnectionError("Connection closed by client")
        buffer += chunk

    # Split at first newline
    msg_data, _ = buffer.split(b'\n', 1)
    return json.loads(msg_data.decode('utf-8'))


def server_session_key_establishment(client_sock: socket.socket) -> bytes:
    """
    Section 2.3: Post-Authentication Session Key Establishment

    After successful authentication, perform DH key exchange to establish a chat session key.

    Server Flow:
    1. Receive DHClientMessage with {p, g, A}
    2. Generate server DH keypair (b, B) where B = g^b mod p
    3. Compute shared secret Ks = A^b mod p
    4. Derive session key K = Trunc16(SHA256(big-endian(Ks)))
    5. Send DHServerMessage with {B}

    Args:
        client_sock: Connected client socket

    Returns:
        16-byte AES-128 session key
    """
    print("\n[SERVER] Starting Session Key Establishment (Section 2.3)...")

    # Step 1: Receive DHClientMessage
    print("[SERVER] Waiting for DHClientMessage from client...")
    request = receive_message(client_sock)
    dh_client_msg = DHClientMessage.model_validate(request)

    print(f"[SERVER] Received DH parameters:")
    print(f"         - Prime p: {dh_client_msg.p.bit_length()} bits")
    print(f"         - Generator g: {dh_client_msg.g}")
    print(f"         - Client public A: {dh_client_msg.A.bit_length()} bits")

    # Step 2: Generate server DH keypair
    print("[SERVER] Generating DH keypair...")
    server_private_key, server_public_key = generate_dh_keypair(
        dh_client_msg.p,
        dh_client_msg.g
    )
    print(f"[SERVER] Public key B: {server_public_key.bit_length()} bits")

    # Step 3: Compute shared secret
    print("[SERVER] Computing shared secret...")
    shared_secret = compute_shared_secret(
        peer_public_key=dh_client_msg.A,
        private_key=server_private_key,
        p=dh_client_msg.p
    )

    # Step 4: Derive session key
    print("[SERVER] Deriving AES-128 session key...")
    session_key = derive_aes_key(shared_secret)
    print(f"[SERVER] Session key established: {session_key.hex()}")

    # Step 5: Send DHServerMessage
    print("[SERVER] Sending DHServerMessage to client...")
    dh_server_msg = DHServerMessage(B=server_public_key)
    send_message(client_sock, dh_server_msg)

    print("[SERVER] ✓ Session Key Establishment complete!")

    return session_key


def send_chat_message(
    client_sock: socket.socket,
    plaintext: str,
    session_key: bytes,
    seqno: int,
    private_key
) -> None:
    """
    Section 2.4: Send an encrypted and signed chat message.

    Message Transmission Process (PDF Page 4-5, Section 1.3):
    1. Pad plaintext (PKCS#7) and encrypt with AES-128 using session_key
    2. Compute digest: h = SHA256(seqno || timestamp || ciphertext)
    3. Sign digest with sender's RSA private key
    4. Send as ChatMessage

    Args:
        client_sock: Connected client socket
        plaintext: Message to send
        session_key: 16-byte AES-128 key from DH exchange
        seqno: Sequence number (strictly increasing)
        private_key: Sender's RSA private key for signing

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

    send_message(client_sock, chat_msg)
    print(f"[SERVER] Sent message #{seqno}: '{plaintext}' (encrypted)")


def receive_chat_message(
    client_sock: socket.socket,
    session_key: bytes,
    expected_seqno: int,
    peer_cert
) -> tuple[str, int]:
    """
    Section 2.4: Receive, verify, and decrypt a chat message.

    Recipient Verification Process (PDF Page 4, Section 1.3):
    1. Check seqno is strictly increasing (replay protection)
    2. Verify signature using sender's certificate and recomputed hash
    3. Decrypt ciphertext with AES-128 and remove PKCS#7 padding

    Args:
        client_sock: Connected client socket
        session_key: 16-byte AES-128 key from DH exchange
        expected_seqno: Expected sequence number (for replay protection)
        peer_cert: Sender's X.509 certificate for signature verification

    Returns:
        Tuple of (plaintext_message, next_expected_seqno)

    Raises:
        ValueError: With "REPLAY" if seqno doesn't match expected
        ValueError: With "SIG_FAIL" if signature verification fails
        ValueError: If decryption fails (padding error)
    """
    # Step 1: Receive ChatMessage
    response = receive_message(client_sock)
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

    print(f"[SERVER] Received message #{chat_msg.seqno}: '{plaintext}' (decrypted)")

    # Return plaintext and next expected sequence number
    return plaintext, expected_seqno + 1


def main():
    """
    Main server workflow.

    Protocol Flow:
    1. Listen for connections
    2. PKI Handshake (Section 2.1)
    3. Certificate Verification (Section 2.1)
    4. Authentication (Section 2.2)
    5. Session Key Establishment (Section 2.3) <- IMPLEMENTED
    6. Chat Loop (Section 2.4) <- IMPLEMENTED
    7. Session Receipt Generation (Section 2.5)
    """
    print("=" * 80)
    print("SecureChat Server")
    print("=" * 80)

    # TODO: Implement full server workflow
    # For now, this is a skeleton showing where functions fit

    print("\n[INFO] Server workflow not fully implemented yet.")
    print("[INFO] Available functions:")
    print("       Section 2.3: server_session_key_establishment(client_sock)")
    print("       Section 2.4: send_chat_message(client_sock, plaintext, session_key, seqno, private_key)")
    print("       Section 2.4: receive_chat_message(client_sock, session_key, expected_seqno, peer_cert)")
    print("\n[INFO] To test Section 2.4, run: python tests/test_section_2.4.py")

    # Example of complete workflow:
    # server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # server_sock.bind(('localhost', 5000))
    # server_sock.listen(5)
    # client_sock, addr = server_sock.accept()
    # ... PKI handshake ...
    # ... Authentication ...
    # session_key = server_session_key_establishment(client_sock)  # Section 2.3
    #
    # # Chat loop (Section 2.4)
    # server_private_key = load_private_key('certs/server_key.pem')
    # client_cert = load_certificate('certs/client_cert.pem')
    # send_seqno = 1
    # recv_seqno = 1
    #
    # while True:
    #     msg, recv_seqno = receive_chat_message(client_sock, session_key, recv_seqno, client_cert)
    #     print(f"Client: {msg}")
    #
    #     response = generate_response(msg)
    #     send_chat_message(client_sock, response, session_key, send_seqno, server_private_key)
    #     send_seqno += 1


if __name__ == "__main__":
    main()
