from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import datetime
import os
from common import config
import json

# f.Implement mechanisms for certificate revocation in case of compromise or expiration
class CRLManager:
    def __init__(self, ca_name):
        self.ca_name = ca_name
        self.crl_path = os.path.join(config.DATA_DIR, f"{ca_name}_crl.json")
        self.revoked_certs = self._load_revoked_certs()
    
    def _load_revoked_certs(self):
        """从文件加载已吊销证书列表"""
        if os.path.exists(self.crl_path):
            try:
                with open(self.crl_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[ERROR] Failed to load revoked certificates: {e}")
                return {'revoked_serials': [], 'last_update': None}
        else:
            return {'revoked_serials': [], 'last_update': None}
    
    def _save_revoked_certs(self):
        """保存已吊销证书列表到文件"""
        try:
            self.revoked_certs['last_update'] = datetime.datetime.utcnow().isoformat()
            with open(self.crl_path, 'w') as f:
                json.dump(self.revoked_certs, f)
        except Exception as e:
            print(f"[ERROR] Failed to save revoked certificates: {e}")
    
    def revoke_certificate(self, cert_serial_number, reason="unspecified"):
        """吊销指定序列号的证书"""
        if str(cert_serial_number) not in self.revoked_certs['revoked_serials']:
            self.revoked_certs['revoked_serials'].append(str(cert_serial_number))
            self._save_revoked_certs()
            print(f"[INFO] Certificate with serial {cert_serial_number} revoked for reason: {reason}")
            return True
        print(f"[INFO] Certificate with serial {cert_serial_number} is already revoked.")
        return False
    
    def is_revoked(self, cert_serial_number):
        """检查证书是否被吊销"""
        is_revoked = str(cert_serial_number) in self.revoked_certs['revoked_serials']
        print(f"[INFO] Certificate with serial {cert_serial_number} revoked status: {is_revoked}")
        return is_revoked
    
    def create_crl(self, ca_private_key, ca_cert):
        """创建X.509标准的CRL"""
        try:
            builder = x509.CertificateRevocationListBuilder()
            builder = builder.issuer_name(ca_cert.subject)
            builder = builder.last_update(datetime.datetime.utcnow())
            builder = builder.next_update(datetime.datetime.utcnow() + datetime.timedelta(days=7))
            
            for serial in self.revoked_certs['revoked_serials']:
                revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                    int(serial)
                ).revocation_date(
                    datetime.datetime.utcnow()
                ).build()
                builder = builder.add_revoked_certificate(revoked_cert)
            
            crl = builder.sign(
                private_key=ca_private_key,
                algorithm=hashes.SHA256()
            )
            print(f"[INFO] CRL created successfully.")
            return crl
        except Exception as e:
            print(f"[ERROR] Failed to create CRL: {e}")
            return None
    
    def save_crl(self, crl, output_path=None):
        """保存CRL到文件"""
        try:
            if output_path is None:
                output_path = os.path.join(config.DATA_DIR, f"{self.ca_name}_crl.pem")
            
            with open(output_path, 'wb') as f:
                f.write(crl.public_bytes(serialization.Encoding.PEM))
            print(f"[INFO] CRL saved to {output_path}")
            return output_path
        except Exception as e:
            print(f"[ERROR] Failed to save CRL: {e}")
            return None
    
    def load_crl(self, crl_path=None):
        """从文件加载CRL"""
        try:
            if crl_path is None:
                crl_path = os.path.join(config.DATA_DIR, f"{self.ca_name}_crl.pem")
            
            if not os.path.exists(crl_path):
                print(f"[INFO] CRL file not found at {crl_path}")
                return None
            
            with open(crl_path, 'rb') as f:
                crl = x509.load_pem_x509_crl(f.read())
                print(f"[INFO] CRL loaded successfully from {crl_path}")
                return crl
        except Exception as e:
            print(f"[ERROR] Failed to load CRL: {e}")
            return None

def verify_cert_with_crl(cert, issuer_crl):
    """检查证书是否在CRL中"""
    try:
        for revoked_cert in issuer_crl:
            if revoked_cert.serial_number == cert.serial_number:
                print(f"[INFO] Certificate with serial {cert.serial_number} is revoked.")
                return False
        print(f"[INFO] Certificate with serial {cert.serial_number} is valid.")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to verify certificate with CRL: {e}")
        return False