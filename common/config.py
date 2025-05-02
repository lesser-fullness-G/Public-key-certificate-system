import os
import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(BASE_DIR, "data")
KEY_DIR = os.path.join(DATA_DIR, "keys")
CERT_DIR = os.path.join(DATA_DIR, "certs")
REQUEST_DIR = os.path.join(DATA_DIR, "requests")
LOG_DIR = os.path.join(DATA_DIR, "logs")

def init_directories():
    os.makedirs(KEY_DIR, exist_ok=True)
    os.makedirs(CERT_DIR, exist_ok=True)
    os.makedirs(REQUEST_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

def cleanup_old_logs(retention_days=7):
    """清理超过保留期的日志文件"""
    try:
        now = datetime.datetime.now()
        for log_file in os.listdir(LOG_DIR):
            log_file_path = os.path.join(LOG_DIR, log_file)
            if os.path.isfile(log_file_path):
                file_creation_time = datetime.datetime.fromtimestamp(os.path.getctime(log_file_path))
                if (now - file_creation_time).days > retention_days:
                    os.remove(log_file_path)
                    print(f"[INFO] Deleted old log file: {log_file}")
    except Exception as e:
        print(f"[ERROR] Failed to clean up old logs: {e}")

def archive_old_logs(retention_days=7):
    """将超过保留期的日志文件归档"""
    try:
        archive_dir = os.path.join(LOG_DIR, "archive")
        os.makedirs(archive_dir, exist_ok=True)

        now = datetime.datetime.now()
        for log_file in os.listdir(LOG_DIR):
            log_file_path = os.path.join(LOG_DIR, log_file)
            if os.path.isfile(log_file_path):
                file_creation_time = datetime.datetime.fromtimestamp(os.path.getctime(log_file_path))
                if (now - file_creation_time).days > retention_days:
                    archived_path = os.path.join(archive_dir, log_file)
                    os.rename(log_file_path, archived_path)
                    print(f"[INFO] Archived old log file: {log_file}")
    except Exception as e:
        print(f"[ERROR] Failed to archive old logs: {e}")