from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from common import config
import datetime
import os
from ca.crl_utils import verify_cert_with_crl
from cryptography.hazmat.backends import default_backend

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

# 证书签发后，通过verify_cert函数验证证书的有效性
def verify_cert(cert_path, ca_cert_path=None, crl_path=None):
    """Verify a certificate's validity"""
    try:
        # Load certificate
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
            print(f"[INFO] Loaded certificate data: {cert_data[:100]}...")
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Get current time in UTC
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # Verify certificate signature
        print("[INFO] Verifying certificate signature...")
        if ca_cert_path:
            with open(ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        
        # Verify validity period
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            print(f"[ERROR] Certificate is not valid at current time")
            return False
        
        # Verify against CRL if provided
        if crl_path:
            with open(crl_path, 'rb') as f:
                crl = x509.load_pem_x509_crl(f.read(), default_backend())
            for revoked_cert in crl:
                if revoked_cert.serial_number == cert.serial_number:
                    print(f"[ERROR] Certificate is revoked")
                    return False
        
        return True
    except Exception as e:
        print(f"[ERROR] Verification failed: {str(e)}")
        return False

# b.证书签发核心功能的实现
# 证书的关键属性：client_id, ca_cert, ca_private_key, csr.public_key， output_path, datetime
def sign_csr(csr_path, ca_cert, ca_private_key, output_path):
    # 加载 CSR
    with open(csr_path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())

    # 创建证书
    cert = x509.CertificateBuilder().subject_name(
        # 使用CSR的主题名称（包含client_id的Common Name）作为证书的主题名称
        csr.subject
    ).issuer_name(
        # 使用CA证书的主题名称作为证书的颁发者名称
        ca_cert.subject
    ).public_key(
        # 使用CSR的公钥作为证书的公钥
        csr.public_key()
    ).serial_number(
        # 使用随机数生成器生成证书的序列号
        x509.random_serial_number()
    ).not_valid_before(
        # 设置证书的有效期开始时间
        datetime.datetime.utcnow()
    ).not_valid_after(
        # 设置证书的有效期结束时间
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_private_key, hashes.SHA256())

    # 保存证书
    with open(output_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[✓] Signed and issued certificate: {output_path}")
    return cert

def generate_csr(subname, public_key, private_key):

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subname)])).sign(private_key, hashes.SHA256())

    #保存私钥
    key_path = os.path.join(config.KEY_DIR, f"{subname}_key.pem")
    with open(key_path,"wb") as f:
        f.write(private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        ))

    # 保存CSR
    csr_path = os.path.join(config.REQUEST_DIR,f"{subname}.csr")
    with open(csr_path,"wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"[✓] {subname} generated and submitted CSR to {csr_path}.")
    return csr_path

def revoke_certificate(cert_path, crl_path):
    """Revoke a certificate and update the CRL."""
    try:
        # Load the certificate to be revoked
        cert = load_cert(cert_path)

        # Load or create the CRL
        if os.path.exists(crl_path):
            with open(crl_path, 'rb') as f:
                crl = x509.load_pem_x509_crl(f.read(), default_backend())
        else:
            crl = x509.CertificateRevocationListBuilder()

        # Revoke the certificate
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            cert.serial_number
        ).revocation_date(
            datetime.datetime.utcnow()
        ).build(default_backend())

        crl = crl.add_revoked_certificate(revoked_cert)

        # Save the updated CRL
        with open(crl_path, 'wb') as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

        print(f"[✓] Certificate revoked and CRL updated: {crl_path}")
    except Exception as e:
        print(f"[ERROR] Failed to revoke certificate: {e}")

def list_certificates(directory):
    """List all certificates in the specified directory."""
    try:
        cert_files = [f for f in os.listdir(directory) if f.endswith('.crt')]
        print(f"[INFO] Certificates in {directory}:")
        for cert_file in cert_files:
            print(f" - {cert_file}")
        return cert_files
    except Exception as e:
        print(f"[ERROR] Failed to list certificates: {e}")
        return []