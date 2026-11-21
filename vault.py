"""Bot env variables ko Redis mein encrypt karke rakhta hai (Fernet)."""
import base64, hashlib, json
from cryptography.fernet import Fernet, InvalidToken
import auth

_f = Fernet(base64.urlsafe_b64encode(hashlib.sha256((auth.SECRET + "|vault").encode()).digest()))


def encrypt_dict(d: dict) -> str:
    return _f.encrypt(json.dumps(d).encode()).decode()


def decrypt_dict(token: str) -> dict:
    if not token:
        return {}
    try:
        return json.loads(_f.decrypt(token.encode()).decode())
    except (InvalidToken, ValueError):
        return {}
