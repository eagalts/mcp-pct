"""Самоподписанный TLS-сертификат агента (EC P-256, 10 лет) на имя или IP хоста. Вызывает install.ps1.

  python gen_cert.py <имя или IP> <каталог tls> <каталог pylib с cryptography>
"""
import datetime
import ipaddress
import sys
from pathlib import Path

name, out, pylib = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, pylib)
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

key = ec.generate_private_key(ec.SECP256R1())
try:
    san = x509.IPAddress(ipaddress.ip_address(name))
except ValueError:
    san = x509.DNSName(name)
now = datetime.datetime.now(datetime.timezone.utc)
subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
(out / "agent.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
(out / "agent.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
print(f"сертификат: {out / 'agent.crt'} ({name})")
