from client import client_utils
from common import config
from ca import cert_utils
import os

def register_client(client_id):
    """注册客户端，生成密钥对 + 加密请求 + 由 CA 签发证书"""
    priv, pub = client_utils.prepare_client(client_id)

    csr_path = client_utils.generate_csr(client_id, pub, priv)

    # 加载 CA 的公钥用于加密 CSR
    ca_cert_path = os.path.join(config.CERT_DIR, "SubCA1.crt")
    ca_cert = cert_utils.load_cert(ca_cert_path)
    ca_public_key = ca_cert.public_key()

    # 加密 CSR
    encrypted_csr_path = client_utils.encrypt_csr(csr_path, ca_public_key)

    print(f"[✓] Encrypted CSR for {client_id} saved to {encrypted_csr_path}")
    return encrypted_csr_path

def list_clients():
    """列出所有已注册的客户端"""
    clients = client_utils.list_registered_clients()
    print("[INFO] Registered clients:")
    for client in clients:
        print(f" - {client}")
    return clients

def delete_client(client_id):
    """删除指定客户端的密钥和请求"""
    print(f"[*] Deleting keys and requests for {client_id}...")
    client_utils.delete_client_keys(client_id)

    csr_path = os.path.join(config.REQUEST_DIR, f"{client_id}.csr")
    encrypted_csr_path = os.path.join(config.REQUEST_DIR, f"{client_id}.enc.csr")

    if os.path.exists(csr_path):
        os.remove(csr_path)
        print(f"[INFO] Deleted CSR for {client_id}.")
    else:
        print(f"[WARNING] CSR for {client_id} not found.")

    if os.path.exists(encrypted_csr_path):
        os.remove(encrypted_csr_path)
        print(f"[INFO] Deleted encrypted CSR for {client_id}.")
    else:
        print(f"[WARNING] Encrypted CSR for {client_id} not found.")
