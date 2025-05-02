import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_key_pair():
    """生成 RSA 密钥对"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filepath):
    with open(filepath, 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

def save_public_key(public_key, filepath):
    with open(filepath, 'wb') as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def load_private_key(filepath):
    with open(filepath, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(filepath):
    with open(filepath, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def load_client_keys_and_certificate(client_id):
    """加载客户端的密钥和证书"""
    # 加载客户端的公钥
    client_public_key_path = os.path.join(config.KEY_DIR, f"{client_id}_public.pem")
    client_public_key = load_public_key(client_public_key_path)

    # 加载客户端的私钥
    client_private_key_path = os.path.join(config.KEY_DIR, f"{client_id}_private.pem")
    client_private_key = load_private_key(client_private_key_path)

    # 加载客户端的证书
    client_cert_path = os.path.join(config.CERT_DIR, f"{client_id}.crt")
    client_cert = cert_utils.load_cert(client_cert_path)

    print(f"[INFO] Loaded keys and certificate for {client_id}.")
    return client_public_key, client_private_key, client_cert

def verify_client_certificate(client_id, ca_cert_path):
    """验证客户端证书的有效性"""
    try:
        client_cert_path = os.path.join(config.CERT_DIR, f"{client_id}.crt")
        is_valid = cert_utils.verify_cert(client_cert_path, ca_cert_path)
        print(f"[INFO] Certificate for {client_id} is valid: {is_valid}")
        return is_valid
    except Exception as e:
        print(f"[ERROR] Failed to verify certificate for {client_id}: {e}")
        return False

def revoke_client_certificate(client_id, crl_manager):
    """吊销客户端证书"""
    try:
        client_cert_path = os.path.join(config.CERT_DIR, f"{client_id}.crt")
        client_cert = cert_utils.load_cert(client_cert_path)
        crl_manager.revoke_certificate(client_cert.serial_number)
        print(f"[INFO] Certificate for {client_id} has been revoked.")
    except Exception as e:
        print(f"[ERROR] Failed to revoke certificate for {client_id}: {e}")