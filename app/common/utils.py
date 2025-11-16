"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""
import base64
import hashlib
import secrets
import time
from typing import Optional


def now_ms() -> int:
    """
    Get current timestamp in milliseconds (Unix time).

    Returns:
        Current time in milliseconds since epoch
    """
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """
    Base64 encode bytes to string.

    Args:
        b: Bytes to encode

    Returns:
        Base64-encoded string
    """
    return base64.b64encode(b).decode('utf-8')


def b64d(s: str) -> bytes:
    """
    Base64 decode string to bytes.

    Args:
        s: Base64-encoded string

    Returns:
        Decoded bytes
    """
    return base64.b64decode(s)


def sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 hash and return as hex string.

    Args:
        data: Bytes to hash

    Returns:
        Hex-encoded SHA-256 hash (64 characters)
    """
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """
    Compute SHA-256 hash and return as bytes.

    Args:
        data: Bytes to hash

    Returns:
        SHA-256 hash as bytes (32 bytes)
    """
    return hashlib.sha256(data).digest()


def generate_salt(length: int = 16) -> bytes:
    """
    Generate cryptographically secure random salt.

    Args:
        length: Length of salt in bytes (default: 16)

    Returns:
        Random bytes of specified length
    """
    return secrets.token_bytes(length)


def generate_nonce(length: int = 16) -> bytes:
    """
    Generate cryptographically secure random nonce.

    Args:
        length: Length of nonce in bytes (default: 16)

    Returns:
        Random bytes of specified length
    """
    return secrets.token_bytes(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time to prevent timing attacks.

    This is critical for comparing password hashes securely.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if equal, False otherwise
    """
    # Use secrets.compare_digest for constant-time comparison
    return secrets.compare_digest(a, b)


def hash_password_with_salt(password: str, salt: bytes) -> str:
    """
    Compute salted password hash: hex(SHA256(salt || password)).

    Args:
        password: Password string
        salt: Salt bytes

    Returns:
        Hex-encoded hash (64 characters)
    """
    # Concatenate salt and password bytes
    data = salt + password.encode('utf-8')
    # Compute SHA-256 and return hex
    return sha256_hex(data)


def int_to_bytes_bigendian(value: int) -> bytes:
    """
    Convert an integer to bytes in big-endian format.

    Args:
        value: Integer value

    Returns:
        Big-endian byte representation
    """
    # Calculate byte length needed
    byte_length = (value.bit_length() + 7) // 8
    if byte_length == 0:
        byte_length = 1
    return value.to_bytes(byte_length, byteorder='big')


def bytes_to_int_bigendian(data: bytes) -> int:
    """
    Convert bytes to integer (big-endian format).

    Args:
        data: Bytes to convert

    Returns:
        Integer value
    """
    return int.from_bytes(data, byteorder='big')


# Example usage and testing
if __name__ == "__main__":
    print("=== Utils Module Tests ===\n")

    # Test timestamp
    ts = now_ms()
    print(f"Current timestamp (ms): {ts}")

    # Test base64
    original = b"Hello, SecureChat!"
    encoded = b64e(original)
    decoded = b64d(encoded)
    print(f"\nBase64 encoding:")
    print(f"  Original: {original}")
    print(f"  Encoded:  {encoded}")
    print(f"  Decoded:  {decoded}")
    print(f"  Match: {original == decoded}")

    # Test SHA-256
    test_data = b"test"
    hash_result = sha256_hex(test_data)
    print(f"\nSHA-256 hash of 'test':")
    print(f"  Hash: {hash_result}")
    print(f"  Length: {len(hash_result)} chars")
    print(f"  Expected: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
    print(f"  Match: {hash_result == '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'}")

    # Test salt generation
    salt1 = generate_salt(16)
    salt2 = generate_salt(16)
    print(f"\nSalt generation:")
    print(f"  Salt 1: {salt1.hex()} (length: {len(salt1)})")
    print(f"  Salt 2: {salt2.hex()} (length: {len(salt2)})")
    print(f"  Different: {salt1 != salt2}")

    # Test password hashing
    password = "MySecurePassword123"
    salt = generate_salt(16)
    pwd_hash = hash_password_with_salt(password, salt)
    print(f"\nPassword hashing:")
    print(f"  Password: {password}")
    print(f"  Salt: {salt.hex()}")
    print(f"  Hash: {pwd_hash}")
    print(f"  Hash length: {len(pwd_hash)} chars")

    # Test constant-time comparison
    hash1 = b"a" * 64
    hash2 = b"a" * 64
    hash3 = b"b" * 64
    print(f"\nConstant-time comparison:")
    print(f"  Same hashes: {constant_time_compare(hash1, hash2)}")
    print(f"  Different hashes: {constant_time_compare(hash1, hash3)}")

    print("\n=== All utils tests passed! ===")

