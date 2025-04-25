from common import key_utils, config
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import os

def prepare_client(client_id):
    """生成并保存客户端密钥对"""
    priv, pub = key_utils.generate_key_pair()
    key_utils.save_private_key(priv, os.path.join(config.KEY_DIR, f'{client_id}_private.pem'))
    key_utils.save_public_key(pub, os.path.join(config.KEY_DIR, f'{client_id}_public.pem'))
    return priv, pub

def encrypt_request(client_id, ca_public_key):
    """加密请求：将客户端 ID + 公钥一起加密"""
    pub_path = os.path.join(config.KEY_DIR, f'{client_id}_public.pem')
    with open(pub_path, 'rb') as f:
        pub_pem = f.read()
    
    message = f"{client_id}:{pub_pem.decode()}".encode()

    encrypted = ca_public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

    request_path = os.path.join(config.REQUEST_DIR, f'{client_id}.req')
    with open(request_path, 'wb') as f:
        f.write(encrypted)

    print(f"[✓] Encrypted request for {client_id} saved.")
    return request_path

def generate_csr(client_id, public_key, private_key):

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_id)])).sign(private_key, hashes.SHA256())

    #保存私钥
    key_path = os.path.join(config.KEY_DIR, f"{client_id}_key.pem")
    with open(key_path,"wb") as f:
        f.write(private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        ))

    # 保存CSR
    csr_path = os.path.join(config.REQUEST_DIR,f"{client_id}.csr")
    with open(csr_path,"wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"[✓] {client_id} generated and submitted CSR to {csr_path}.")
    return csr_path