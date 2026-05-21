import os
from configparser import ConfigParser
from dotenv import load_dotenv

load_dotenv()

_DEFAULT_SENSITIVE_FILES = [
    ".env", ".env.backup", "config.php", "wp-config.php",
    "database.yml", "settings.py", "secrets.yml", "backup.sql",
    ".DS_Store", "composer.json", "package.json",
]


def get_sensitive_files() -> list[str]:
    parser = ConfigParser()
    parser.read("config.ini")
    raw = parser.get("SENSITIVE_FILES", "files_to_check", fallback="").strip()
    if raw:
        return [f.strip() for f in raw.split(",") if f.strip()]
    return _DEFAULT_SENSITIVE_FILES


REQUEST_TIMEOUT: int = int(os.getenv("SCAN_TIMEOUT", "5"))
MAX_THREADS: int = int(os.getenv("SCAN_THREADS", "5"))
