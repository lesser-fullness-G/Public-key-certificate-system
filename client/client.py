from client import client_utils
from common import config
from ca import cert_utils
import os

#def register_client(client_id, ca_cert, ca_private_key):
def register_client(client_id):
    """注册客户端，生成密钥对 + 加密请求 + 由 CA 签发证书"""
    #_, pub = client_utils.prepare_client(client_id)
    priv, pub = client_utils.prepare_client(client_id)

    return client_utils.generate_csr(client_id,pub,priv)

    #cert = cert_utils.create_signed_cert(client_id, _, pub, ca_cert, ca_private_key)
    #cert_path = os.path.join(config.CERT_DIR, f'{client_id}.crt')
    #cert_utils.save_cert(cert, cert_path)
    #print(f"[✓] Certificate issued to {client_id}.")
