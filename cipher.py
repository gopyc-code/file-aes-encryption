import base64
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    def __init__(self, key: bytes):
        self.__key = hashlib.sha256(key).digest()
        self.__bs = AES.block_size

    def encrypt_text(self, raw_text: str) -> bytes:
        text = pad(raw_text.encode('utf-8'), self.__bs)
        iv = get_random_bytes(self.__bs)
        cipher = AES.new(self.__key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(text))

    def decrypt_text(self, raw_bytes: bytes) -> str:
        data = base64.b64decode(raw_bytes)
        iv = data[:self.__bs]
        cipher = AES.new(self.__key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(data[self.__bs:]), self.__bs)
        return decrypted.decode('utf-8')

    def encrypt_file(self, file_name: str) -> None:
        with open(file_name, 'rb') as source_file, \
             open(f"{file_name}.bin", "wb") as encrypted_file:
            file_content = source_file.read()
            encrypted_file.write(self.encrypt_text(file_content.decode('utf-8')))

    def decrypt_file(self, file_name: str) -> None:
        with open(f"{file_name}.bin", 'rb') as source_file, \
             open(file_name, "wb") as decrypted_file:
            decrypted_content = self.decrypt_text(source_file.read())
            decrypted_file.write(decrypted_content.encode('utf-8'))


def generate_key(length: int = 16) -> bytes:
    return get_random_bytes(length)


if __name__ == "__main__":
    key = generate_key()
    cipher = AESCipher(key)

    source_text = "hello world"
    encrypted_text = cipher.encrypt_text(source_text)
    decrypted_text = cipher.decrypt_text(encrypted_text)
    print(source_text == decrypted_text)
