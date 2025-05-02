from common import key_utils, config
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os
import json

# c.Implements the client registration functionality
def prepare_client(client_id):
    """生成并保存客户端密钥对"""
    # 生成RSA密钥对 
    priv, pub = key_utils.generate_key_pair()
    # 保存私钥
    key_utils.save_private_key(priv, os.path.join(config.KEY_DIR, f'{client_id}_private.pem'))
    # 保存公钥
    key_utils.save_public_key(pub, os.path.join(config.KEY_DIR, f'{client_id}_public.pem'))
    return priv, pub

# Add a function to list all registered clients
def list_registered_clients():
    """列出所有已注册的客户端"""
    try:
        client_files = [f for f in os.listdir(config.KEY_DIR) if f.endswith('_public.pem')]
        clients = [os.path.splitext(f)[0].replace('_public', '') for f in client_files]
        print("[INFO] Registered clients:")
        for client in clients:
            print(f" - {client}")
        return clients
    except Exception as e:
        print(f"[ERROR] Failed to list registered clients: {e}")
        return []

# Add a function to delete a client's keys
def delete_client_keys(client_id):
    """删除指定客户端的密钥对"""
    try:
        private_key_path = os.path.join(config.KEY_DIR, f'{client_id}_private.pem')
        public_key_path = os.path.join(config.KEY_DIR, f'{client_id}_public.pem')

        if os.path.exists(private_key_path):
            os.remove(private_key_path)
            print(f"[INFO] Deleted private key for {client_id}.")
        else:
            print(f"[WARNING] Private key for {client_id} not found.")

        if os.path.exists(public_key_path):
            os.remove(public_key_path)
            print(f"[INFO] Deleted public key for {client_id}.")
        else:
            print(f"[WARNING] Public key for {client_id} not found.")
    except Exception as e:
        print(f"[ERROR] Failed to delete keys for {client_id}: {e}")

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

def encrypt_csr(csr_bytes, ca_public_key):
    """使用混合加密方案加密CSR：AES加密CSR，RSA加密AES密钥"""
    try:
        # 1. 生成AES密钥和IV
        aes_key = os.urandom(32)  # 256位AES密钥
        iv = os.urandom(16)       # 128位IV
        
        # 2. 使用AES-CBC加密CSR
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(csr_bytes) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_csr = encryptor.update(padded_data) + encryptor.finalize()
        
        # 3. 使用RSA加密AES密钥和IV
        # 将AES密钥和IV打包在一起
        key_data = json.dumps({
            'aes_key': aes_key.hex(),
            'iv': iv.hex()
        }).encode()
        
        # 使用RSA加密
        encrypted_key = ca_public_key.encrypt(
            key_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 4. 将加密后的数据和密钥打包
        encrypted_data = {
            'encrypted_csr': encrypted_csr.hex(),
            'encrypted_key': encrypted_key.hex()
        }
        
        return json.dumps(encrypted_data).encode()
    except Exception as e:
        print(f"[ERROR] Failed to encrypt CSR: {e}")
        return None

# b.证书请求CSR生成
def generate_csr(client_id, public_key, private_key, ca_public_key=None):
    """生成CSR并可选加密"""
    # 创建CSR，包含client_id作为主题名称Common Name
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_id)])
    ).sign(private_key, hashes.SHA256())
    
    # 保存私钥
    key_path = os.path.join(config.KEY_DIR, f"{client_id}_key.pem")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # 获取CSR的PEM格式
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    
    # 如果提供了CA公钥，则加密CSR
    if ca_public_key:
        print(f"[INFO] Encrypting CSR for {client_id} using hybrid encryption...")
        encrypted_csr = encrypt_csr(csr_pem, ca_public_key)
        if encrypted_csr:
            # 保存加密的CSR
            csr_path = os.path.join(config.REQUEST_DIR, f"{client_id}.enc.csr")
            with open(csr_path, "wb") as f:
                f.write(encrypted_csr)
            print(f"[✓] {client_id} generated and submitted encrypted CSR to {csr_path}.")
            return csr_path
        else:
            print("[WARNING] Failed to encrypt CSR. Saving unencrypted CSR.")
    
    # 保存未加密的CSR
    csr_path = os.path.join(config.REQUEST_DIR, f"{client_id}.csr")
    with open(csr_path, "wb") as f:
        f.write(csr_pem)
    
    print(f"[✓] {client_id} generated and submitted CSR to {csr_path}.")
    return csr_path