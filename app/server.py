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


def main():
    """
    Main server workflow.

    Protocol Flow:
    1. Listen for connections
    2. PKI Handshake (Section 2.1)
    3. Certificate Verification (Section 2.1)
    4. Authentication (Section 2.2)
    5. Session Key Establishment (Section 2.3) <- IMPLEMENTED
    6. Chat Loop (Section 2.4)
    7. Session Receipt Generation (Section 2.5)
    """
    print("=" * 80)
    print("SecureChat Server")
    print("=" * 80)

    # TODO: Implement full server workflow
    # For now, this is a skeleton showing where Section 2.3 fits

    print("\n[INFO] Server workflow not fully implemented yet.")
    print("[INFO] Section 2.3 (Session Key Establishment) function available:")
    print("       - server_session_key_establishment(client_sock)")
    print("\n[INFO] To test Section 2.3, run: python tests/test_section_2.3.py")

    # Example of where Section 2.3 would be called:
    # server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # server_sock.bind(('localhost', 5000))
    # server_sock.listen(5)
    # client_sock, addr = server_sock.accept()
    # ... PKI handshake ...
    # ... Authentication ...
    # session_key = server_session_key_establishment(client_sock)  # <- Section 2.3
    # ... Use session_key for encrypted chat (Section 2.4) ...


if __name__ == "__main__":
    main()
