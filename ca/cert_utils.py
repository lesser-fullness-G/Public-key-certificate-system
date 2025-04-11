from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
import os

def create_self_signed_cert(name, private_key, public_key):
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)\
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow())\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
        .sign(private_key, hashes.SHA256())
    return cert

def create_signed_cert(subject_name, private_key, public_key, issuer_cert, issuer_key):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    issuer = issuer_cert.subject
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)\
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow())\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
        .sign(issuer_key, hashes.SHA256())
    return cert

def save_cert(cert, path):
    with open(path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_cert(path):
    with open(path, 'rb') as f:
        cert_data = f.read()
        print(f"[INFO] Loaded certificate data: {cert_data[:100]}...")  # 打印部分内容查看
        return x509.load_pem_x509_certificate(cert_data)

def verify_cert(cert, issuer_public_key):
    try:
        print(f"[INFO] Verifying certificate with issuer public key...")
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        print("[✓] Certificate is valid.")
        return True
    except Exception as e:
        print(f"[ERROR] Verification failed: {e}")
        return False