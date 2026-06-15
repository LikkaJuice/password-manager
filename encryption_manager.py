import os
from cryptography.fernet import Fernet  # pip install cryptography


class EncryptionManager:
    """
    Управляет шифрованием и дешифрованием.

    В __init__:
    - проверяет наличие файла ключа (.key);
    - если он есть — считывает ключ;
    - если его нет — создаёт, записывает и использует новый ключ.
    """

    def __init__(self, key_file: str = ".key"):
        self.key_file = key_file
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)

    def _load_or_create_key(self) -> bytes:
        """
        Загружает ключ из файла или создаёт новый, если файла нет.
        """
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
        return key

    def encrypt(self, data: str) -> bytes:
        """
        Шифрует строку и возвращает зашифрованные байты.
        """
        return self.fernet.encrypt(data.encode("utf-8"))

    def decrypt(self, token: bytes) -> str:
        """
        Дешифрует байты и возвращает исходную строку.
        """
        return self.fernet.decrypt(token).decode("utf-8")