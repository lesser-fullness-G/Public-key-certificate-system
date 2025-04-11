from common import key_utils, config
from ca import cert_utils
import os

def setup_root_ca():
    name = "RootCA"
    key_path = os.path.join(config.KEY_DIR, f"{name}_private.pem")
    pub_path = os.path.join(config.KEY_DIR, f"{name}_public.pem")
    cert_path = os.path.join(config.CERT_DIR, f"{name}.crt")

    # 生成密钥对
    private_key, public_key = key_utils.generate_key_pair()
    key_utils.save_private_key(private_key, key_path)
    key_utils.save_public_key(public_key, pub_path)

    # 自签名证书
    cert = cert_utils.create_self_signed_cert(name, private_key, public_key)
    cert_utils.save_cert(cert, cert_path)

    print(f"[✓] Root CA setup completed.")
    return private_key, cert