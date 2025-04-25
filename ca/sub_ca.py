from common import key_utils, config
from ca import cert_utils
import os

'''def create_sub_ca(sub_name, root_private_key, root_cert):
    key_path = os.path.join(config.KEY_DIR, f"{sub_name}_private.pem")
    pub_path = os.path.join(config.KEY_DIR, f"{sub_name}_public.pem")
    cert_path = os.path.join(config.CERT_DIR, f"{sub_name}.crt")

    private_key, public_key = key_utils.generate_key_pair()
    key_utils.save_private_key(private_key, key_path)
    key_utils.save_public_key(public_key, pub_path)

    print(f"[INFO] Signing certificate for {sub_name} using Root CA's private key...")
    cert = cert_utils.create_signed_cert(sub_name, private_key, public_key, root_cert, root_private_key)
    cert_utils.save_cert(cert, cert_path)
    print(f"[✓] Sub CA '{sub_name}' created.")
    return private_key, cert '''

def get_sub_ca(sub_name):
    key_path = os.path.join(config.KEY_DIR, f"{sub_name}_private.pem")
    pub_path = os.path.join(config.KEY_DIR, f"{sub_name}_public.pem")
    cert_path = os.path.join(config.CERT_DIR, f"{sub_name}.crt")

    private_key, public_key = key_utils.generate_key_pair()
    key_utils.save_private_key(private_key, key_path)
    key_utils.save_public_key(public_key, pub_path)

    csr_path = cert_utils.generate_csr(sub_name, public_key, private_key)
    return csr_path,private_key


def subCA_sign_csr(sub_name,csr_path, ca_cert, ca_private_key):
    output_path = os.path.join(config.CERT_DIR, f"{sub_name}.crt")
    cert_utils.sign_csr(csr_path, ca_cert, ca_private_key, output_path)
