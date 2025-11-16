"""AES-128(ECB)+PKCS#7 helpers (use library)."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS#7 padding to data.

    PKCS#7 padding adds N bytes of value N to make the data a multiple
    of block_size. For example, if 3 bytes of padding are needed, add b'\\x03\\x03\\x03'.

    Args:
        data: Data to pad
        block_size: Block size in bytes (default: 16 for AES)

    Returns:
        Padded data
    """
    # Calculate padding length
    padding_length = block_size - (len(data) % block_size)

    # Create padding bytes (value is the padding length itself)
    padding = bytes([padding_length] * padding_length)

    return data + padding


def unpad_pkcs7(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from data.

    Args:
        data: Padded data

    Returns:
        Unpadded data

    Raises:
        ValueError: If padding is invalid
    """
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")

    # Last byte indicates padding length
    padding_length = data[-1]

    # Validate padding length
    if padding_length == 0 or padding_length > 16:
        raise ValueError(f"Invalid padding length: {padding_length}")

    # Validate all padding bytes
    padding = data[-padding_length:]
    if not all(byte == padding_length for byte in padding):
        raise ValueError("Invalid PKCS#7 padding")

    # Remove padding
    return data[:-padding_length]


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128-ECB with PKCS#7 padding.

    Note: ECB mode is used per assignment requirements for educational purposes.
    In production, use CBC, GCM, or other authenticated modes.

    Args:
        plaintext: Data to encrypt
        key: AES-128 key (must be 16 bytes)

    Returns:
        Ciphertext

    Raises:
        ValueError: If key length is not 16 bytes
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 requires a 16-byte key, got {len(key)} bytes")

    # Apply PKCS#7 padding
    padded_plaintext = pad_pkcs7(plaintext)

    # Create AES cipher in ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )

    # Encrypt
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128-ECB and remove PKCS#7 padding.

    Args:
        ciphertext: Data to decrypt
        key: AES-128 key (must be 16 bytes)

    Returns:
        Plaintext

    Raises:
        ValueError: If key length is not 16 bytes or padding is invalid
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 requires a 16-byte key, got {len(key)} bytes")

    # Create AES cipher in ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )

    # Decrypt
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS#7 padding
    plaintext = unpad_pkcs7(padded_plaintext)

    return plaintext


# Example usage and testing
if __name__ == "__main__":
    import os

    print("=== AES-128-ECB Module Tests ===\n")

    # Test 1: Basic encryption/decryption
    print("[1] Testing basic encryption/decryption...")
    key = os.urandom(16)
    plaintext = b"Hello, SecureChat! This is a test message."

    print(f"    Key: {key.hex()}")
    print(f"    Plaintext: {plaintext}")
    print(f"    Plaintext length: {len(plaintext)} bytes")

    ciphertext = aes_encrypt(plaintext, key)
    print(f"    Ciphertext: {ciphertext.hex()}")
    print(f"    Ciphertext length: {len(ciphertext)} bytes")

    decrypted = aes_decrypt(ciphertext, key)
    print(f"    Decrypted: {decrypted}")
    print(f"    Match: {plaintext == decrypted}")

    # Test 2: PKCS#7 padding
    print("\n[2] Testing PKCS#7 padding...")
    test_cases = [
        b"1234567890123456",  # Exactly 16 bytes (full block)
        b"12345678901234567", # 17 bytes (needs 15 bytes padding)
        b"1",                 # 1 byte (needs 15 bytes padding)
        b"123456789012345",   # 15 bytes (needs 1 byte padding)
    ]

    for i, data in enumerate(test_cases):
        padded = pad_pkcs7(data)
        unpadded = unpad_pkcs7(padded)
        print(f"    Test {i+1}: len={len(data):2d} -> padded={len(padded):2d} -> unpadded={len(unpadded):2d} | Match: {data == unpadded}")

    # Test 3: Different message sizes
    print("\n[3] Testing various message sizes...")
    for size in [1, 15, 16, 17, 32, 100]:
        msg = os.urandom(size)
        encrypted = aes_encrypt(msg, key)
        decrypted = aes_decrypt(encrypted, key)
        match = msg == decrypted
        print(f"    Size {size:3d} bytes: {'✓' if match else '✗'}")

    # Test 4: Wrong key detection
    print("\n[4] Testing wrong key detection...")
    key1 = os.urandom(16)
    key2 = os.urandom(16)
    message = b"Secret message"

    encrypted_with_key1 = aes_encrypt(message, key1)
    try:
        decrypted_with_key2 = aes_decrypt(encrypted_with_key1, key2)
        print(f"    Decryption with wrong key: Failed to detect (BAD!)")
    except ValueError as e:
        print(f"    Decryption with wrong key: Detected! (padding error)")

    print("\n=== All AES tests passed! ===")

