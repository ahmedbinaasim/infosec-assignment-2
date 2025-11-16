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


def main():
    """
    Main client workflow.

    Protocol Flow:
    1. PKI Connect (Section 2.1)
    2. Certificate Verification (Section 2.1)
    3. Registration or Login (Section 2.2)
    4. Session Key Establishment (Section 2.3) <- IMPLEMENTED
    5. Encrypted Chat (Section 2.4)
    6. Session Receipt (Section 2.5)
    """
    print("=" * 80)
    print("SecureChat Client")
    print("=" * 80)

    # TODO: Implement full client workflow
    # For now, this is a skeleton showing where Section 2.3 fits

    print("\n[INFO] Client workflow not fully implemented yet.")
    print("[INFO] Section 2.3 (Session Key Establishment) function available:")
    print("       - client_session_key_establishment(sock)")
    print("\n[INFO] To test Section 2.3, run: python tests/test_section_2.3.py")

    # Example of where Section 2.3 would be called:
    # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sock.connect(('localhost', 5000))
    # ... PKI handshake ...
    # ... Registration/Login ...
    # session_key = client_session_key_establishment(sock)  # <- Section 2.3
    # ... Use session_key for encrypted chat (Section 2.4) ...


if __name__ == "__main__":
    main()
