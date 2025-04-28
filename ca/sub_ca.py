from common import key_utils, config
from ca import cert_utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography import x509
import os
import json

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

def decrypt_csr(encrypted_csr_path, private_key):
    """解密使用混合加密的CSR请求"""
    try:
        # 1. 读取加密的CSR数据
        with open(encrypted_csr_path, "rb") as f:
            encrypted_data = json.loads(f.read().decode())
        
        # 2. 使用RSA解密AES密钥和IV
        encrypted_key = bytes.fromhex(encrypted_data['encrypted_key'])
        key_data = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 3. 解析AES密钥和IV
        key_info = json.loads(key_data.decode())
        aes_key = bytes.fromhex(key_info['aes_key'])
        iv = bytes.fromhex(key_info['iv'])
        
        # 4. 使用AES解密CSR
        encrypted_csr = bytes.fromhex(encrypted_data['encrypted_csr'])
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_csr) + decryptor.finalize()
        
        # 5. 移除填充
        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted_csr = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        # 6. 解析CSR
        csr = x509.load_pem_x509_csr(decrypted_csr)
        return csr
    except Exception as e:
        print(f"[ERROR] Failed to decrypt CSR: {e}")
        return None

def subCA_sign_csr(sub_name, csr_path, ca_cert, ca_private_key):
    """对CSR进行签名，支持加密的CSR"""
    output_path = os.path.join(config.CERT_DIR, f"{sub_name}.crt")
    
    # 检查是否是加密的CSR
    if csr_path.endswith('.enc.csr'):
        print(f"[INFO] Detected encrypted CSR for {sub_name}, attempting to decrypt...")
        csr = decrypt_csr(csr_path, ca_private_key)
        if csr:
            print(f"[✓] Successfully decrypted CSR for {sub_name}.")
            
            # 创建并保存临时解密的CSR文件
            temp_csr_path = os.path.join(config.REQUEST_DIR, f"{sub_name}.temp.csr")
            with open(temp_csr_path, "wb") as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))
            
            # 签发证书
            cert = cert_utils.sign_csr(temp_csr_path, ca_cert, ca_private_key, output_path)
            
            # 删除临时CSR文件
            os.remove(temp_csr_path)
            return cert
        else:
            raise Exception(f"Failed to decrypt CSR for {sub_name}")
    else:
        # 处理未加密的CSR
        return cert_utils.sign_csr(csr_path, ca_cert, ca_private_key, output_path)
