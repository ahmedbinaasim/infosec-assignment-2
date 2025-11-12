"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""
import argparse
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def load_ca(ca_dir: Path):
    """
    Load CA private key and certificate from directory.

    Args:
        ca_dir: Directory containing ca_key.pem and ca_cert.pem

    Returns:
        Tuple of (ca_private_key, ca_certificate)
    """
    ca_key_path = ca_dir / "ca_key.pem"
    ca_cert_path = ca_dir / "ca_cert.pem"

    if not ca_key_path.exists() or not ca_cert_path.exists():
        raise FileNotFoundError(
            f"CA files not found in {ca_dir}. "
            f"Please run gen_ca.py first to generate the Root CA."
        )

    # Load CA private key
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_certificate = x509.load_pem_x509_certificate(f.read(), backend=default_backend())

    return ca_private_key, ca_certificate


def issue_certificate(
    common_name: str,
    output_path: Path,
    ca_private_key,
    ca_certificate,
    cert_type: str = "server"
):
    """
    Issue a certificate signed by the Root CA.

    Args:
        common_name: CN for the certificate (e.g., "server.local", "client.local")
        output_path: Path prefix for saving cert/key (e.g., "certs/server")
        ca_private_key: CA's private key for signing
        ca_certificate: CA's certificate
        cert_type: "server" or "client" (affects Extended Key Usage)
    """
    # Generate RSA private key for the entity (2048 bits)
    print(f"[*] Generating 2048-bit RSA keypair for '{common_name}'...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Create subject for the certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Set validity period (365 days / 1 year)
    now = datetime.datetime.utcnow()
    not_valid_before = now
    not_valid_after = now + datetime.timedelta(days=365)  # 1 year

    print(f"[*] Creating X.509 certificate signed by CA...")
    print(f"    Subject: CN={common_name}")
    print(f"    Type: {cert_type}")
    print(f"    Validity: {not_valid_before.date()} to {not_valid_after.date()}")

    # Build the certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)  # Issuer is the CA
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        # NOT a CA certificate
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        # Key usage for end-entity certificate
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Subject Alternative Name (SAN) - CRITICAL per assignment
        # SAN = DNSName(CN)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
            ]),
            critical=False,
        )
        # Subject Key Identifier
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        # Authority Key Identifier (links to CA)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
    )

    # Extended Key Usage based on cert type
    if cert_type == "server":
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    elif cert_type == "client":
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )

    # Sign the certificate with CA's private key
    certificate = cert_builder.sign(ca_private_key, hashes.SHA256(), backend=default_backend())

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save private key
    key_file = Path(str(output_path) + "_key.pem")
    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print(f"[+] Private key saved to: {key_file}")

    # Save certificate
    cert_file = Path(str(output_path) + "_cert.pem")
    with open(cert_file, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Certificate saved to: {cert_file}")

    print(f"\n[SUCCESS] Certificate for '{common_name}' issued successfully!")
    print(f"          To inspect: openssl x509 -text -in {cert_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Issue a certificate signed by the Root CA"
    )
    parser.add_argument(
        "--cn",
        type=str,
        required=True,
        help="Common Name (CN) for the certificate (e.g., 'server.local', 'client.local')"
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output path prefix for cert/key files (e.g., 'certs/server')"
    )
    parser.add_argument(
        "--type",
        type=str,
        choices=["server", "client"],
        default="server",
        help="Certificate type: 'server' or 'client' (default: server)"
    )
    parser.add_argument(
        "--ca-dir",
        type=Path,
        default=Path("certs"),
        help="Directory containing CA files (default: ./certs)"
    )

    args = parser.parse_args()

    # Load CA
    print(f"[*] Loading CA from {args.ca_dir}...")
    ca_private_key, ca_certificate = load_ca(args.ca_dir)
    print(f"[+] CA loaded: {ca_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")

    # Issue certificate
    issue_certificate(
        common_name=args.cn,
        output_path=args.out,
        ca_private_key=ca_private_key,
        ca_certificate=ca_certificate,
        cert_type=args.type
    )


if __name__ == "__main__":
    main()
