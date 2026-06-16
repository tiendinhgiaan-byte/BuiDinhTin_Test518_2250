import os

import ecdsa

KEY_DIR = os.path.join("cipher", "ecc", "keys")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "privateKey.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "publicKey.pem")

if not os.path.exists(KEY_DIR):
    os.makedirs(KEY_DIR)


class ECCCipher:
    """Mat ma duong cong Elliptic (ECDSA): tao khoa, ky va xac thuc chu ky."""

    def __init__(self):
        pass

    def generate_keys(self):
        sk = ecdsa.SigningKey.generate()          # Tao khoa rieng tu
        vk = sk.get_verifying_key()               # Lay khoa cong khai tu khoa rieng tu
        with open(PRIVATE_KEY_PATH, "wb") as p:
            p.write(sk.to_pem())
        with open(PUBLIC_KEY_PATH, "wb") as p:
            p.write(vk.to_pem())

    def load_keys(self):
        with open(PRIVATE_KEY_PATH, "rb") as p:
            sk = ecdsa.SigningKey.from_pem(p.read())
        with open(PUBLIC_KEY_PATH, "rb") as p:
            vk = ecdsa.VerifyingKey.from_pem(p.read())
        return sk, vk

    def sign(self, message, key):
        # Ky du lieu bang khoa rieng tu
        return key.sign(message.encode("ascii"))

    def verify(self, message, signature, key):
        _, vk = self.load_keys()
        try:
            return vk.verify(signature, message.encode("ascii"))
        except ecdsa.BadSignatureError:
            return False