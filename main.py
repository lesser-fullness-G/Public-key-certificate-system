from ca import root_ca, sub_ca, cert_utils
from client import client
from common import config, key_utils
import os

def main():
    # 初始化目录结构
    config.init_directories()

    # 1. 设置 Root CA
    print("[*] Initializing Root CA...")
    root_private_key, root_cert = root_ca.setup_root_ca()

    # 2. 创建 Sub CA
    print("[*] Creating Sub CA...")
    sub_ca_private_key, sub_ca_cert = sub_ca.create_sub_ca("SubCA1", root_private_key, root_cert)

    # 3. 客户端注册（生成密钥对，提交请求）
    print("[*] Registering Client A...")
    client_id = "ClientA"
    client.register_client(client_id, root_cert, root_private_key)

    print("[*] Registering Client B...")
    client_id = "ClientB"
    client.register_client(client_id, root_cert, root_private_key)

    print("[*] Registering Client C...")
    client_id = "ClientC"
    client.register_client(client_id, root_cert, root_private_key)

    # 4. 验证签发的证书（验证客户端证书）
    print("[*] Verifying Client A's certificate...")
    cert_path = os.path.join(config.CERT_DIR, "ClientA.crt")
    cert = cert_utils.load_cert(cert_path)
    is_valid = cert_utils.verify_cert(cert, root_cert.public_key())
    print(f"Client A Certificate Valid: {is_valid}")

    print("[*] Verifying Client B's certificate...")
    cert_path = os.path.join(config.CERT_DIR, "ClientB.crt")
    cert = cert_utils.load_cert(cert_path)
    is_valid = cert_utils.verify_cert(cert, root_cert.public_key())
    print(f"Client B Certificate Valid: {is_valid}")

    print("[*] Verifying Client C's certificate...")
    cert_path = os.path.join(config.CERT_DIR, "ClientC.crt")
    cert = cert_utils.load_cert(cert_path)
    is_valid = cert_utils.verify_cert(cert, root_cert.public_key())
    print(f"Client C Certificate Valid: {is_valid}")

if __name__ == "__main__":
    main()