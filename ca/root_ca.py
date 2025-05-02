from common import key_utils, config
from ca import cert_utils
import os

def setup_root_ca():
    name = "RootCA"
    key_path = os.path.join(config.KEY_DIR, f"{name}_private.pem")
    pub_path = os.path.join(config.KEY_DIR, f"{name}_public.pem")
    cert_path = os.path.join(config.CERT_DIR, f"{name}.crt")

    # 生成密钥对
    # 检查文件是否存在，如果存在则加载现有密钥对和证书，否则生成新的密钥对和证书
    if not os.path.exists(cert_path) and not os.path.exists(key_path) and not os.path.exists(pub_path):
        # Generate private/publickey pair by the function in key_utils
        private_key, public_key = key_utils.generate_key_pair()
        # Create self-signed certificate (自签名证书)
        cert = cert_utils.create_self_signed_cert(name, private_key, public_key)
        # Save private/public key pair and certificate(分别保存私钥和公钥和证书)
        key_utils.save_private_key(private_key, key_path)
        key_utils.save_public_key(public_key, pub_path)
        cert_utils.save_cert(cert, cert_path)
        print(f"[✓] Root CA setup completed.")
        print(f"[✓] Generated new Root CA with name: {name}")
    else:
        private_key = key_utils.load_private_key(key_path)
        public_key = key_utils.load_public_key(pub_path)
        cert = cert_utils.load_cert(cert_path)
        print(f"[✓] Loaded existing Root CA with name: {name}")

    return private_key, public_key, cert

def rootCA_sign_csr(sub_name, csr_path, root_cert, root_private_key):
    output_path = os.path.join(config.CERT_DIR, f"{sub_name}.crt")
    return cert_utils.sign_csr(csr_path,root_cert,root_private_key,output_path)

# Add a function to revoke a certificate
def revoke_certificate(cert_path):
    crl_path = os.path.join(config.CRL_DIR, "RootCA_crl.pem")
    if not os.path.exists(crl_path):
        crl = crl_utils.create_crl()
    else:
        crl = crl_utils.load_crl(crl_path)

    cert = cert_utils.load_cert(cert_path)
    crl = crl_utils.revoke_cert(cert, crl)
    crl_utils.save_crl(crl, crl_path)
    print(f"[✓] Certificate revoked and CRL updated: {crl_path}")
