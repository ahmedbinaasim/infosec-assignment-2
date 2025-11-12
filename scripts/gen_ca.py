"""Create Root CA (RSA + self-signed X.509) using cryptography."""
import argparse
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_root_ca(ca_name: str, output_dir: Path):
    """
    Generate a self-signed Root CA certificate and private key.

    Args:
        ca_name: Common Name for the CA (e.g., "FAST-NU Root CA")
        output_dir: Directory to save ca_key.pem and ca_cert.pem
    """
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate RSA private key (2048 bits)
    print(f"[*] Generating 2048-bit RSA keypair for CA...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Create subject for CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])

    # Set validity period (10 years)
    now = datetime.datetime.utcnow()
    not_valid_before = now
    not_valid_after = now + datetime.timedelta(days=3650)  # 10 years

    print(f"[*] Creating self-signed X.509 certificate...")
    print(f"    Subject: CN={ca_name}")
    print(f"    Validity: {not_valid_before.date()} to {not_valid_after.date()}")

    # Build the certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        # Critical: Mark as CA certificate
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        # Key usage for CA
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,  # Can sign certificates
                crl_sign=True,       # Can sign CRLs
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Subject Key Identifier
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )

    # Self-sign the certificate
    certificate = cert_builder.sign(private_key, hashes.SHA256(), backend=default_backend())

    # Save private key
    key_path = output_dir / "ca_key.pem"
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print(f"[+] CA private key saved to: {key_path}")

    # Save certificate
    cert_path = output_dir / "ca_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    print(f"[+] CA certificate saved to: {cert_path}")

    print(f"\n[SUCCESS] Root CA created successfully!")
    print(f"          To inspect: openssl x509 -text -in {cert_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate a self-signed Root CA")
    parser.add_argument(
        "--name",
        type=str,
        default="FAST-NU Root CA",
        help="Common Name (CN) for the Root CA (default: 'FAST-NU Root CA')"
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("certs"),
        help="Output directory for CA files (default: ./certs)"
    )

    args = parser.parse_args()

    generate_root_ca(args.name, args.out)


if __name__ == "__main__":
    main()
