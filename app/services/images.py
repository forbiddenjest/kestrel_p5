"""Cloud image integrity validation."""
import hashlib, re
from urllib.parse import urlparse

def validate_image_url(url: str, checksum: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and bool(parsed.hostname) and bool(re.fullmatch(r"[a-fA-F0-9]{64}", checksum))

def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""): digest.update(chunk)
    return digest.hexdigest()
