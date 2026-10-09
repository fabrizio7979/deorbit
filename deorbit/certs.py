"""Create a development CA and a server certificate signed by it.

    python -m deorbit.certs [HOST ...]

The robot has to trust ``ca.crt``. A CA already present in the output
directory is reused, so the server certificate can be reissued for other
hostnames without touching the robot again.

The server calls ``generate`` itself when it starts without a certificate,
unless the ``generate_certs`` setting is off.
"""

import argparse
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# The name a robot reconfigured for this server connects to. A stock robot
# derives a production hostname instead: orbital.neatocloud.com for vendor N,
# orbital.ksecosys.com for 3, orbital.orbital.professional.vorwerk.com for 1/2.
DEFAULT_HOSTS = ["orbital.deorbit"]

_KEY_USAGES = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
)


def _key_usage(*enabled: str) -> x509.KeyUsage:
    return x509.KeyUsage(**{usage: usage in enabled for usage in _KEY_USAGES})


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _builder(subject: x509.Name, issuer: x509.Name, public_key: rsa.RSAPublicKey, days: int) -> x509.CertificateBuilder:
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    )


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as file:
        file.write(pem)


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _san(host: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)


def generate(cert_path: Path, key_path: Path, hosts: list[str], days: int = 3650) -> Path:
    """Write a server certificate and its key, and return the path of the CA certificate.

    The CA is ``ca.crt`` beside the certificate, with ``ca.key`` beside the
    key. It is created unless both are already there.
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    ca_cert_path, ca_key_path = cert_path.with_name("ca.crt"), key_path.with_name("ca.key")
    if ca_cert_path.exists() and ca_key_path.exists():
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    else:
        # RSA rather than EC throughout, for the sake of old TLS stacks.
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = _name("deorbit development CA")
        ca_cert = (
            _builder(ca_name, ca_name, ca_key.public_key(), days)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_key_usage("key_cert_sign", "crl_sign"), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        _write_key(ca_key_path, ca_key)
        _write_cert(ca_cert_path, ca_cert)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        _builder(_name(hosts[0]), ca_cert.subject, key.public_key(), days)
        .add_extension(x509.SubjectAlternativeName([_san(host) for host in hosts]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage("digital_signature", "key_encipherment"), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(key_path, key)
    _write_cert(cert_path, cert)
    return ca_cert_path


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m deorbit.certs", description=__doc__.splitlines()[0])
    parser.add_argument("hosts", nargs="*", metavar="HOST", default=DEFAULT_HOSTS,
                        help="hostnames or IP addresses the robot connects to (default: %(default)s)")
    parser.add_argument("--out", type=Path, default=Path("certs"), help="output directory (default: %(default)s)")
    args = parser.parse_args()
    ca = generate(args.out / "server.crt", args.out / "server.key", args.hosts)
    print(f"server certificate for {', '.join(args.hosts)} written to {args.out}/")
    print(f"robots must trust {ca}")


if __name__ == "__main__":
    main()
