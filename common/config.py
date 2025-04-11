import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(BASE_DIR, "data")
KEY_DIR = os.path.join(DATA_DIR, "keys")
CERT_DIR = os.path.join(DATA_DIR, "certs")
REQUEST_DIR = os.path.join(DATA_DIR, "requests")

def init_directories():
    os.makedirs(KEY_DIR, exist_ok=True)
    os.makedirs(CERT_DIR, exist_ok=True)
    os.makedirs(REQUEST_DIR, exist_ok=True)