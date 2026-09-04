"""
Week 3 — FIX the misuse here. Fill in the TODOs.
pip install argon2-cffi pycryptodome
"""
import os, hashlib, secrets
from argon2 import PasswordHasher
from Crypto.Cipher import AES

ph = PasswordHasher()

def store_password(pw: str) -> str:
    # FIX: argon2id, salted automatically
    return ph.hash(pw)

def verify_password(hash_: str, pw: str) -> bool:
    try:
        return ph.verify(hash_, pw)
    except Exception:
        return False

def login_and_migrate(username: str, password_attempt: str, user_db: dict) -> bool:
    """Task 6: Rehash-on-login path that upgrades a legacy MD5 record to argon2id."""
    record = user_db.get(username)
    if not record:
        return False
    stored_hash = record["hash"]

    # Check if legacy unsalted MD5 (32-character hexadecimal)
    if len(stored_hash) == 32 and all(c in "0123456789abcdefABCDEF" for c in stored_hash):
        if hashlib.md5(password_attempt.encode()).hexdigest() == stored_hash:
            # Rehash with Argon2id and update the database
            user_db[username]["hash"] = store_password(password_attempt)
            user_db[username]["type"] = "argon2id"
            print(f"[MIGRATION] Successfully upgraded '{username}' from MD5 to Argon2id!")
            return True
        return False
    else:
        return verify_password(stored_hash, password_attempt)

def encrypt_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    # FIX: authenticated encryption (AES-GCM), random nonce, key from env/KMS
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce, ct, tag

def decrypt_gcm(nonce: bytes, ct: bytes, tag: bytes, key: bytes) -> bytes:
    """Task 7: Authenticated decryption with tag verification."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def reset_token() -> str:
    # FIX: CSPRNG (CWE-330 remediation)
    return secrets.token_urlsafe(16)

if __name__ == "__main__":
    key = bytes.fromhex(os.environ.get("ENC_KEY_HEX", os.urandom(32).hex()))
    
    print("=== Task 9 / Task 6: Password Hashing & Migration ===")
    h = store_password("password123")
    print("argon2 ok:", verify_password(h, "password123"))

    # Simulation of legacy migration
    test_db = {
        "alice": {"hash": hashlib.md5(b"alicepw").hexdigest(), "type": "md5"}
    }
    print("Before login:", test_db["alice"])
    login_and_migrate("alice", "alicepw", test_db)
    print("After login:", test_db["alice"]["type"], test_db["alice"]["hash"][:30] + "...")

    print("\n=== Task 7: AES-GCM Authenticated Encryption ===")
    secret_msg = b"confidential patient record"
    nonce, ct, tag = encrypt_gcm(secret_msg, key)
    print("Nonce:", nonce.hex())
    print("Ciphertext:", ct.hex())
    print("Auth Tag:", tag.hex())

    # Successful round-trip
    decrypted = decrypt_gcm(nonce, ct, tag, key)
    print("Decrypted plaintext:", decrypted.decode())

    # Tampered byte check
    tampered_ct = bytes([ct[0] ^ 0x01]) + ct[1:]
    try:
        decrypt_gcm(nonce, tampered_ct, tag, key)
        print("Tamper check: FAILED (did not catch tamper!)")
    except ValueError as e:
        print("Tamper check: SUCCESS -> Integrity verification caught alteration:", e)

    print("\n=== Task 3 / Task 9: CSPRNG Token ===")
    print("token:", reset_token())
