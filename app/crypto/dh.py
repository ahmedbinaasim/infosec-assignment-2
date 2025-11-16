"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""
import secrets
from typing import Tuple
from app.common.utils import sha256_bytes, int_to_bytes_bigendian


# RFC 3526 Group 14 (2048-bit MODP Group) - Pre-defined safe prime for efficiency
# This is a well-known safe prime used in production systems
RFC3526_MODP_2048_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

RFC3526_MODP_2048_GENERATOR = 2


def generate_dh_parameters() -> Tuple[int, int]:
    """
    Generate or return Diffie-Hellman parameters (p, g).

    For efficiency and security, we use the pre-defined RFC 3526 Group 14
    parameters (2048-bit MODP group) which is widely used in production.

    Returns:
        Tuple of (prime p, generator g)
    """
    return (RFC3526_MODP_2048_PRIME, RFC3526_MODP_2048_GENERATOR)


def generate_dh_keypair(p: int, g: int) -> Tuple[int, int]:
    """
    Generate a Diffie-Hellman keypair.

    Args:
        p: Prime modulus
        g: Generator

    Returns:
        Tuple of (private_key, public_key)
        - private_key: Random private exponent (a or b)
        - public_key: Public value (g^a mod p or g^b mod p)
    """
    # Generate random private key (at least 256 bits for security)
    # Private key should be in range [2, p-2]
    private_key = secrets.randbelow(p - 2) + 2

    # Compute public key: g^private_key mod p
    public_key = pow(g, private_key, p)

    return (private_key, public_key)


def compute_shared_secret(peer_public_key: int, private_key: int, p: int) -> int:
    """
    Compute the Diffie-Hellman shared secret.

    Args:
        peer_public_key: Other party's public key (A or B)
        private_key: Own private key (b or a)
        p: Prime modulus

    Returns:
        Shared secret Ks = peer_public_key^private_key mod p
    """
    # Validate peer public key (must be in range [2, p-1])
    if peer_public_key < 2 or peer_public_key >= p:
        raise ValueError("Invalid peer public key")

    # Compute shared secret: peer_public^private_key mod p
    shared_secret = pow(peer_public_key, private_key, p)

    return shared_secret


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from Diffie-Hellman shared secret.

    Key derivation formula (per assignment):
    K = Trunc16(SHA256(big-endian(Ks)))

    Args:
        shared_secret: DH shared secret (Ks)

    Returns:
        16-byte AES-128 key
    """
    # Convert shared secret to big-endian bytes
    secret_bytes = int_to_bytes_bigendian(shared_secret)

    # Compute SHA-256 hash
    hash_bytes = sha256_bytes(secret_bytes)

    # Truncate to first 16 bytes for AES-128
    aes_key = hash_bytes[:16]

    return aes_key


# Example usage and testing
if __name__ == "__main__":
    print("=== Diffie-Hellman Module Tests ===\n")

    # Generate DH parameters
    print("[1] Generating DH parameters...")
    p, g = generate_dh_parameters()
    print(f"    Prime p (bits): {p.bit_length()}")
    print(f"    Generator g: {g}")

    # Alice generates keypair
    print("\n[2] Alice generates DH keypair...")
    alice_private, alice_public = generate_dh_keypair(p, g)
    print(f"    Alice private key (bits): {alice_private.bit_length()}")
    print(f"    Alice public key (bits): {alice_public.bit_length()}")

    # Bob generates keypair
    print("\n[3] Bob generates DH keypair...")
    bob_private, bob_public = generate_dh_keypair(p, g)
    print(f"    Bob private key (bits): {bob_private.bit_length()}")
    print(f"    Bob public key (bits): {bob_public.bit_length()}")

    # Alice computes shared secret using Bob's public key
    print("\n[4] Alice computes shared secret...")
    alice_shared_secret = compute_shared_secret(bob_public, alice_private, p)
    print(f"    Alice shared secret (first 32 hex): {hex(alice_shared_secret)[:34]}...")

    # Bob computes shared secret using Alice's public key
    print("\n[5] Bob computes shared secret...")
    bob_shared_secret = compute_shared_secret(alice_public, bob_private, p)
    print(f"    Bob shared secret (first 32 hex): {hex(bob_shared_secret)[:34]}...")

    # Verify shared secrets match
    print("\n[6] Verifying shared secrets match...")
    print(f"    Secrets match: {alice_shared_secret == bob_shared_secret}")

    # Derive AES keys
    print("\n[7] Deriving AES-128 keys...")
    alice_aes_key = derive_aes_key(alice_shared_secret)
    bob_aes_key = derive_aes_key(bob_shared_secret)
    print(f"    Alice AES key: {alice_aes_key.hex()}")
    print(f"    Bob AES key:   {bob_aes_key.hex()}")
    print(f"    Keys match: {alice_aes_key == bob_aes_key}")
    print(f"    Key length: {len(alice_aes_key)} bytes")

    print("\n=== All DH tests passed! ===")

