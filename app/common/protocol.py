"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""
from typing import Optional, Literal
from pydantic import BaseModel, Field


# Control Plane Messages (Section 1.1)

class HelloMessage(BaseModel):
    """Client hello message with certificate."""
    type: Literal["hello"] = "hello"
    client_cert: str = Field(..., description="PEM-encoded X.509 certificate")
    nonce: str = Field(..., description="Base64-encoded random nonce for freshness")


class ServerHelloMessage(BaseModel):
    """Server hello response with certificate."""
    type: Literal["server_hello"] = "server_hello"
    server_cert: str = Field(..., description="PEM-encoded X.509 certificate")
    nonce: str = Field(..., description="Base64-encoded random nonce")


# Key Agreement Messages (Section 1.2)

class DHClientMessage(BaseModel):
    """Diffie-Hellman client message with public parameters and value."""
    type: Literal["dh_client"] = "dh_client"
    p: int = Field(..., description="DH prime modulus")
    g: int = Field(..., description="DH generator")
    A: int = Field(..., description="Client public DH value (g^a mod p)")


class DHServerMessage(BaseModel):
    """Diffie-Hellman server response with public value."""
    type: Literal["dh_server"] = "dh_server"
    B: int = Field(..., description="Server public DH value (g^b mod p)")


# Authentication Messages

class RegisterMessage(BaseModel):
    """User registration message with credentials."""
    type: Literal["register"] = "register"
    email: str = Field(..., description="User email address")
    username: str = Field(..., description="Unique username")
    pwd: str = Field(..., description="Base64-encoded salted password hash")
    salt: str = Field(..., description="Base64-encoded salt")


class LoginMessage(BaseModel):
    """User login message with credentials."""
    type: Literal["login"] = "login"
    email: str = Field(..., description="User email address")
    pwd: str = Field(..., description="Base64-encoded salted password hash")
    nonce: str = Field(..., description="Base64-encoded nonce for freshness")


class AuthResponseMessage(BaseModel):
    """Authentication response from server."""
    type: Literal["auth_response"] = "auth_response"
    status: Literal["success", "error"] = Field(..., description="Authentication result")
    message: str = Field(..., description="Description or error message")


# Data Plane Messages (Section 1.3)

class ChatMessage(BaseModel):
    """Encrypted chat message with signature."""
    type: Literal["msg"] = "msg"
    seqno: int = Field(..., description="Sequence number for replay protection")
    ts: int = Field(..., description="Unix timestamp in milliseconds")
    ct: str = Field(..., description="Base64-encoded AES ciphertext")
    sig: str = Field(..., description="Base64-encoded RSA signature over SHA256(seqno||ts||ct)")


# Non-Repudiation Messages (Section 1.4)

class SessionReceiptMessage(BaseModel):
    """Signed session receipt for non-repudiation."""
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"] = Field(..., description="Who generated this receipt")
    first_seq: int = Field(..., description="First sequence number in session")
    last_seq: int = Field(..., description="Last sequence number in session")
    transcript_sha256: str = Field(..., description="Hex-encoded SHA-256 hash of transcript")
    sig: str = Field(..., description="Base64-encoded RSA signature over transcript hash")


# Error Messages

class ErrorMessage(BaseModel):
    """Generic error message."""
    type: Literal["error"] = "error"
    code: str = Field(..., description="Error code (e.g., BAD_CERT, SIG_FAIL, REPLAY)")
    message: str = Field(..., description="Human-readable error description")


# Example usage and testing
if __name__ == "__main__":
    import json
    from app.common.utils import b64e, generate_nonce

    print("=== Protocol Models Tests ===\n")

    # Test Hello message
    print("[1] Testing HelloMessage...")
    hello = HelloMessage(
        client_cert="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        nonce=b64e(generate_nonce(16))
    )
    print(f"    {hello.model_dump_json()[:100]}...")

    # Test DH Client message
    print("\n[2] Testing DHClientMessage...")
    dh_client = DHClientMessage(
        p=12345678901234567890,
        g=2,
        A=9876543210987654321
    )
    print(f"    {dh_client.model_dump_json()}")

    # Test Register message
    print("\n[3] Testing RegisterMessage...")
    register = RegisterMessage(
        email="alice@example.com",
        username="alice",
        pwd=b64e(b"hashed_password_here"),
        salt=b64e(generate_nonce(16))
    )
    print(f"    {register.model_dump_json()[:100]}...")

    # Test Chat message
    print("\n[4] Testing ChatMessage...")
    chat = ChatMessage(
        seqno=1,
        ts=1700000000000,
        ct=b64e(b"encrypted_message_here"),
        sig=b64e(b"signature_here")
    )
    print(f"    {chat.model_dump_json()}")

    # Test Session Receipt
    print("\n[5] Testing SessionReceiptMessage...")
    receipt = SessionReceiptMessage(
        peer="server",
        first_seq=1,
        last_seq=10,
        transcript_sha256="abcd1234" * 8,  # 64 hex chars
        sig=b64e(b"signature_here")
    )
    print(f"    {receipt.model_dump_json()[:100]}...")

    # Test Error message
    print("\n[6] Testing ErrorMessage...")
    error = ErrorMessage(
        code="BAD_CERT",
        message="Certificate validation failed: expired"
    )
    print(f"    {error.model_dump_json()}")

    print("\n=== All protocol model tests passed! ===")

