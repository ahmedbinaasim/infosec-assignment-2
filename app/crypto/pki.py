"""X.509 validation: signed-by-CA, validity window, CN/SAN."""
import datetime
from pathlib import Path
from typing import Optional, Union
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class CertificateValidationError(Exception):
    """Base exception for certificate validation errors."""
    pass


class BadCertificateError(CertificateValidationError):
    """Raised when certificate is invalid, self-signed, or untrusted."""
    def __init__(self, message: str):
        super().__init__(f"BAD_CERT: {message}")


class ExpiredCertificateError(CertificateValidationError):
    """Raised when certificate is expired or not yet valid."""
    def __init__(self, message: str):
        super().__init__(f"CERT_EXPIRED: {message}")


class CNMismatchError(CertificateValidationError):
    """Raised when CN/SAN doesn't match expected value."""
    def __init__(self, message: str):
        super().__init__(f"CN_MISMATCH: {message}")


def load_certificate(cert_path: Union[str, Path]) -> x509.Certificate:
    """
    Load an X.509 certificate from a PEM file.

    Args:
        cert_path: Path to the PEM-encoded certificate file

    Returns:
        Loaded X.509 Certificate object

    Raises:
        FileNotFoundError: If certificate file doesn't exist
        ValueError: If file is not a valid PEM certificate
    """
    cert_path = Path(cert_path)
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificate file not found: {cert_path}")

    with open(cert_path, "rb") as f:
        cert_data = f.read()

    try:
        certificate = x509.load_pem_x509_certificate(cert_data, backend=default_backend())
        return certificate
    except Exception as e:
        raise ValueError(f"Invalid PEM certificate: {e}")


def load_certificate_from_pem(pem_data: Union[str, bytes]) -> x509.Certificate:
    """
    Load an X.509 certificate from PEM-encoded data (string or bytes).

    Args:
        pem_data: PEM-encoded certificate data

    Returns:
        Loaded X.509 Certificate object

    Raises:
        ValueError: If data is not a valid PEM certificate
    """
    if isinstance(pem_data, str):
        pem_data = pem_data.encode('utf-8')

    try:
        certificate = x509.load_pem_x509_certificate(pem_data, backend=default_backend())
        return certificate
    except Exception as e:
        raise ValueError(f"Invalid PEM certificate: {e}")


def load_private_key(key_path: Union[str, Path], password: Optional[bytes] = None):
    """
    Load an RSA private key from a PEM file.

    Args:
        key_path: Path to the PEM-encoded private key file
        password: Optional password for encrypted keys

    Returns:
        Loaded RSA private key object

    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If file is not a valid PEM private key
    """
    key_path = Path(key_path)
    if not key_path.exists():
        raise FileNotFoundError(f"Private key file not found: {key_path}")

    with open(key_path, "rb") as f:
        key_data = f.read()

    try:
        private_key = serialization.load_pem_private_key(
            key_data,
            password=password,
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        raise ValueError(f"Invalid PEM private key: {e}")


def get_cert_fingerprint(cert: x509.Certificate) -> str:
    """
    Compute SHA-256 fingerprint of a certificate for logging/identification.

    Args:
        cert: X.509 Certificate object

    Returns:
        Hex-encoded SHA-256 fingerprint string
    """
    fingerprint = cert.fingerprint(hashes.SHA256())
    return fingerprint.hex()


def get_cert_common_name(cert: x509.Certificate) -> Optional[str]:
    """
    Extract the Common Name (CN) from a certificate's subject.

    Args:
        cert: X.509 Certificate object

    Returns:
        Common Name string, or None if not present
    """
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
    except Exception:
        pass
    return None


def get_cert_san_dns_names(cert: x509.Certificate) -> list:
    """
    Extract DNS names from the Subject Alternative Name (SAN) extension.

    Args:
        cert: X.509 Certificate object

    Returns:
        List of DNS names from SAN, or empty list if no SAN extension
    """
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_names = san_ext.value.get_values_for_type(x509.DNSName)
        return list(san_names)
    except x509.ExtensionNotFound:
        return []


def validate_certificate(
    cert: Union[x509.Certificate, str, bytes],
    ca_cert: Union[x509.Certificate, str, bytes],
    expected_cn: Optional[str] = None
) -> bool:
    """
    Validate an X.509 certificate according to assignment requirements.

    Performs three critical checks:
    1. Signature chain validity: Verify cert is signed by the CA
    2. Validity period: Check not_valid_before <= now <= not_valid_after
    3. Common Name/SAN match: If expected_cn provided, verify CN or SAN matches

    Args:
        cert: Certificate to validate (Certificate object, PEM string, or bytes)
        ca_cert: CA certificate for verification (Certificate object, PEM string, or bytes)
        expected_cn: Optional expected Common Name to verify (e.g., "server.local")

    Returns:
        True if certificate is valid

    Raises:
        BadCertificateError: Invalid signature, self-signed, or untrusted
        ExpiredCertificateError: Certificate expired or not yet valid
        CNMismatchError: CN/SAN doesn't match expected_cn
    """
    # Convert to Certificate objects if needed
    if isinstance(cert, (str, bytes)):
        cert = load_certificate_from_pem(cert)
    if isinstance(ca_cert, (str, bytes)):
        ca_cert = load_certificate_from_pem(ca_cert)

    # CHECK 1: Signature chain validity
    # Verify that 'cert' was signed by 'ca_cert'
    try:
        ca_public_key = ca_cert.public_key()

        # Check if this is a self-signed certificate (subject == issuer)
        if cert.subject == cert.issuer:
            raise BadCertificateError("Certificate is self-signed")

        # Verify the signature using CA's public key
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except InvalidSignature:
        raise BadCertificateError("Certificate signature verification failed - not signed by CA")
    except AttributeError as e:
        raise BadCertificateError(f"Invalid certificate or CA format: {e}")

    # CHECK 2: Validity period
    now = datetime.datetime.utcnow()

    if now < cert.not_valid_before:
        raise ExpiredCertificateError(
            f"Certificate not yet valid (valid from {cert.not_valid_before})"
        )

    if now > cert.not_valid_after:
        raise ExpiredCertificateError(
            f"Certificate expired (valid until {cert.not_valid_after})"
        )

    # CHECK 3: Common Name / SAN verification (if expected_cn provided)
    if expected_cn:
        # Check CN in subject
        cert_cn = get_cert_common_name(cert)

        # Check SAN DNS names
        san_names = get_cert_san_dns_names(cert)

        # Match against either CN or any SAN DNS name
        if cert_cn == expected_cn or expected_cn in san_names:
            # Valid match
            pass
        else:
            raise CNMismatchError(
                f"Certificate CN/SAN doesn't match expected '{expected_cn}' "
                f"(CN={cert_cn}, SAN={san_names})"
            )

    # All checks passed
    return True


def verify_certificate_file(
    cert_path: Union[str, Path],
    ca_cert_path: Union[str, Path],
    expected_cn: Optional[str] = None
) -> bool:
    """
    Validate a certificate file against a CA certificate file.

    Convenience wrapper around validate_certificate for file-based validation.

    Args:
        cert_path: Path to certificate PEM file
        ca_cert_path: Path to CA certificate PEM file
        expected_cn: Optional expected Common Name to verify

    Returns:
        True if certificate is valid

    Raises:
        BadCertificateError: Invalid signature, self-signed, or untrusted
        ExpiredCertificateError: Certificate expired or not yet valid
        CNMismatchError: CN/SAN doesn't match expected_cn
        FileNotFoundError: Certificate or CA file not found
    """
    cert = load_certificate(cert_path)
    ca_cert = load_certificate(ca_cert_path)

    return validate_certificate(cert, ca_cert, expected_cn)


# Example usage and testing
if __name__ == "__main__":
    import sys

    # Simple CLI for testing certificate validation
    if len(sys.argv) < 3:
        print("Usage: python -m app.crypto.pki <cert.pem> <ca_cert.pem> [expected_cn]")
        sys.exit(1)

    cert_file = sys.argv[1]
    ca_file = sys.argv[2]
    expected_cn = sys.argv[3] if len(sys.argv) > 3 else None

    try:
        print(f"[*] Validating certificate: {cert_file}")
        print(f"[*] Against CA: {ca_file}")
        if expected_cn:
            print(f"[*] Expected CN: {expected_cn}")

        result = verify_certificate_file(cert_file, ca_file, expected_cn)

        if result:
            cert = load_certificate(cert_file)
            print(f"\n[SUCCESS] Certificate is VALID")
            print(f"          Subject CN: {get_cert_common_name(cert)}")
            print(f"          SAN: {get_cert_san_dns_names(cert)}")
            print(f"          Valid from: {cert.not_valid_before}")
            print(f"          Valid until: {cert.not_valid_after}")
            print(f"          Fingerprint: {get_cert_fingerprint(cert)}")

    except CertificateValidationError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        sys.exit(1)
