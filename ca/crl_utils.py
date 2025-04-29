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
            except Exception:
                return {'revoked_serials': [], 'last_update': None}
        else:
            return {'revoked_serials': [], 'last_update': None}
    
    def _save_revoked_certs(self):
        """保存已吊销证书列表到文件"""
        self.revoked_certs['last_update'] = datetime.datetime.utcnow().isoformat()
        with open(self.crl_path, 'w') as f:
            json.dump(self.revoked_certs, f)
    
    def revoke_certificate(self, cert_serial_number, reason="unspecified"):
        """吊销指定序列号的证书"""
        if str(cert_serial_number) not in self.revoked_certs['revoked_serials']:
            self.revoked_certs['revoked_serials'].append(str(cert_serial_number))
            self._save_revoked_certs()
            return True
        return False
    
    def is_revoked(self, cert_serial_number):
        """检查证书是否被吊销"""
        return str(cert_serial_number) in self.revoked_certs['revoked_serials']
    
    def create_crl(self, ca_private_key, ca_cert):
        """创建X.509标准的CRL"""
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
        return crl
    
    def save_crl(self, crl, output_path=None):
        """保存CRL到文件"""
        if output_path is None:
            output_path = os.path.join(config.DATA_DIR, f"{self.ca_name}_crl.pem")
        
        with open(output_path, 'wb') as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        return output_path
    
    def load_crl(self, crl_path=None):
        """从文件加载CRL"""
        if crl_path is None:
            crl_path = os.path.join(config.DATA_DIR, f"{self.ca_name}_crl.pem")
        
        if not os.path.exists(crl_path):
            return None
        
        with open(crl_path, 'rb') as f:
            return x509.load_pem_x509_crl(f.read())

def verify_cert_with_crl(cert, issuer_crl):
    """检查证书是否在CRL中"""
    for revoked_cert in issuer_crl:
        if revoked_cert.serial_number == cert.serial_number:
            return False
    return True 