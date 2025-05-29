import binascii
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class XPFFHeaderGenerator:
    def __init__(self, base_key: str):
        self.base_key = base_key

    def _derive_xpff_key(self, guest_id: str) -> bytes:
        combined = self.base_key + guest_id
        return hashlib.sha256(combined.encode()).digest()

    def generate_xpff(self, plaintext: str, guest_id: str) -> str:
        key = self._derive_xpff_key(guest_id)
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        return binascii.hexlify(nonce + ciphertext + tag).decode()

    def decode_xpff(self, hex_string: str, guest_id: str) -> str:
        key = self._derive_xpff_key(guest_id)
        raw = binascii.unhexlify(hex_string)
        nonce = raw[:12]
        ciphertext = raw[12:-16]
        tag = raw[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()