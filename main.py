from ca import root_ca, sub_ca, cert_utils, crl_utils
from client import client, client_utils
from common import config, key_utils
import os

def main():
    # 初始化目录结构
    config.init_directories()

    print("\n" + "="*50)
    print("PKI SYSTEM DEMONSTRATION")
    print("="*50 + "\n")

    # 1. 设置 Root CA
    # 使用root_ca.py中的setup_root_ca函数生成根CA的密钥对和自签名证书
    try:
        print("\n[STEP 1] INITIALIZING ROOT CA")
        print("-"*30)
        print("[*] Creating Root CA key pair and self-signed certificate...")
        root_private_key, root_public_key, root_cert = root_ca.setup_root_ca()
        print("[✓] Root CA initialized successfully")
    except Exception as error:
        print(f"[ERROR] Failed to initialize Root CA: {error}")
        return

    # 2. 创建 Sub CA
    try:
        print("\n[STEP 2] CREATING SUB CAS")
        print("-"*30)
        print("[*] Creating Sub CA 1...")
        csr_path_sub1, sub_ca1_private_key = sub_ca.get_sub_ca("SubCA1")

        print("[*] Creating Sub CA 2...")
        csr_path_sub2, sub_ca2_private_key = sub_ca.get_sub_ca("SubCA2")

        print("[*] Root CA signing Sub CA 1 certificate...")
        sub_ca1_cert = root_ca.rootCA_sign_csr("SubCA1", csr_path_sub1, root_cert, root_private_key)

        print("[*] Root CA signing Sub CA 2 certificate...")
        sub_ca2_cert = root_ca.rootCA_sign_csr("SubCA2", csr_path_sub2, root_cert, root_private_key)

        # 创建Sub CA的CRL管理器
        sub_ca1_crl_manager = crl_utils.CRLManager("SubCA1")
        sub_ca2_crl_manager = crl_utils.CRLManager("SubCA2")
        print("[✓] Sub CAs created and initialized successfully")
    except Exception as error:
        print(f"[ERROR] Failed to create Sub CAs: {error}")
        return

    # 3. 客户端注册（生成密钥对，提交CSR）
    try:
        print("\n[STEP 3] CLIENT REGISTRATION")
        print("-"*30)
        # 加载Sub CA的公钥用于加密CSR
        sub_ca1_public_key = sub_ca1_cert.public_key()
        sub_ca2_public_key = sub_ca2_cert.public_key()

        print("[*] Registering Client A with Sub CA 1...")
        client_id = "ClientA"
        priv_a, pub_a = client_utils.prepare_client(client_id)
        csr_path1 = client_utils.generate_csr(client_id, pub_a, priv_a, sub_ca1_public_key)

        print("[*] Registering Client B with Sub CA 1...")
        client_id = "ClientB"
        priv_b, pub_b = client_utils.prepare_client(client_id)
        csr_path2 = client_utils.generate_csr(client_id, pub_b, priv_b, sub_ca1_public_key)

        print("[*] Registering Client C with Sub CA 2...")
        client_id = "ClientC"
        priv_c, pub_c = client_utils.prepare_client(client_id)
        csr_path3 = client_utils.generate_csr(client_id, pub_c, priv_c, sub_ca2_public_key)
        print("[✓] All clients registered successfully")
    except Exception as error:
        print(f"[ERROR] Failed to register clients: {error}")
        return

    # 4. Sub_CA审核并签发证书
    try:
        print("\n[STEP 4] CERTIFICATE ISSUANCE")
        print("-"*30)
        print("[*] Sub CA 1 processing and signing Client A's CSR...")
        client_a_cert = sub_ca.subCA_sign_csr("ClientA", csr_path1, sub_ca1_cert, sub_ca1_private_key)

        print("[*] Sub CA 1 processing and signing Client B's CSR...")
        client_b_cert = sub_ca.subCA_sign_csr("ClientB", csr_path2, sub_ca1_cert, sub_ca1_private_key)

        print("[*] Sub CA 2 processing and signing Client C's CSR...")
        client_c_cert = sub_ca.subCA_sign_csr("ClientC", csr_path3, sub_ca2_cert, sub_ca2_private_key)
        print("[✓] All certificates issued successfully")
    except Exception as e:
        print(f"[ERROR] Failed to issue certificates: {e}")
        return

    # 5. 验证签发的证书
    try:
        print("\n[STEP 5] CERTIFICATE VERIFICATION")
        print("-"*30)
        print("[*] Verifying Client A's certificate...")
        cert_path = os.path.join(config.CERT_DIR, "ClientA.crt")
        ca_cert_path = os.path.join(config.CERT_DIR, "SubCA1.crt")
        is_valid = cert_utils.verify_cert(cert_path, ca_cert_path)
        print(f"  - Client A Certificate Valid: {is_valid}")

        print("[*] Verifying Client B's certificate...")
        cert_path = os.path.join(config.CERT_DIR, "ClientB.crt")
        ca_cert_path = os.path.join(config.CERT_DIR, "SubCA1.crt")
        is_valid = cert_utils.verify_cert(cert_path, ca_cert_path)
        print(f"  - Client B Certificate Valid: {is_valid}")

        print("[*] Verifying Client C's certificate...")
        cert_path = os.path.join(config.CERT_DIR, "ClientC.crt")
        ca_cert_path = os.path.join(config.CERT_DIR, "SubCA2.crt")
        is_valid = cert_utils.verify_cert(cert_path, ca_cert_path)
        print(f"  - Client C Certificate Valid: {is_valid}")
        print("[✓] Certificate verification completed")
    except Exception as e:
        print(f"[ERROR] Failed to verify certificates: {e}")
        return

    # 6. 演示证书吊销
    try:
        print("\n[STEP 6] CERTIFICATE REVOCATION DEMONSTRATION")
        print("-"*30)
        print("[*] Revoking Client B's certificate...")
        cert_b = cert_utils.load_cert(os.path.join(config.CERT_DIR, "ClientB.crt"))
        sub_ca1_crl_manager.revoke_certificate(cert_b.serial_number)

        print("[*] Creating and saving CRL...")
        sub_ca1_crl = sub_ca1_crl_manager.create_crl(sub_ca1_private_key, sub_ca1_cert)
        crl_path = sub_ca1_crl_manager.save_crl(sub_ca1_crl)
        print(f"  - CRL saved to {crl_path}")

        print("\n[*] Verifying certificates with CRL check...")
        print("[*] Verifying Client A's certificate...")
        cert_path = os.path.join(config.CERT_DIR, "ClientA.crt")
        ca_cert_path = os.path.join(config.CERT_DIR, "SubCA1.crt")
        is_valid = cert_utils.verify_cert(cert_path, ca_cert_path, crl_path)
        print(f"  - Client A Certificate Valid: {is_valid}")

        print("[*] Verifying Client B's certificate...")
        cert_path = os.path.join(config.CERT_DIR, "ClientB.crt")
        ca_cert_path = os.path.join(config.CERT_DIR, "SubCA1.crt")
        is_valid = cert_utils.verify_cert(cert_path, ca_cert_path, crl_path)
        print(f"  - Client B Certificate Valid: {is_valid} (should be False due to revocation)")
        print("[✓] Revocation demonstration completed")
    except Exception as e:
        print(f"[ERROR] Failed to demonstrate revocation: {e}")
        return

    print("\n" + "="*50)
    print("PKI SYSTEM DEMONSTRATION COMPLETED SUCCESSFULLY")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()