import getpass
import hashlib
import string
from dataclasses import dataclass
from typing import Optional

from db_manager import DatabaseManager
from encryption_manager import EncryptionManager


@dataclass
class PasswordOptions:
    """
    Опции генерации пароля.
    По умолчанию: 16 символов, все типы символов включены.
    """
    length: int = 16
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_special: bool = True


class PasswordGenerator:
    """
    Основной класс, через который пользователь взаимодействует с приложением.

    Функции:
    - setup_master_password — установка мастер-пароля, если его нет.
    - authenticate — проверка мастер-пароля.
    - generate_password / generate_password_interactive — генерация пароля.
    - add_password — добавление новой записи.
    - get_password — получение пароля по названию.
    - list_passwords — список всех записей.
    - delete_password — удаление записи.
    - show_menu — простое текстовое меню (если понадобится).
    """

    def __init__(self, db: Optional[DatabaseManager] = None, enc: Optional[EncryptionManager] = None):
        self.db = db or DatabaseManager()
        self.enc = enc or EncryptionManager()

    # ------------- мастер-пароль -------------

    def _hash_password(self, password: str) -> str:
        """
        Возвращает SHA-256 хэш строки.
        """
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def setup_master_password(self) -> None:
        """
        Установка мастер-пароля при первом запуске.
        Если мастер-пароль уже есть, ничего не делает.
        """
        existing_hash = self.db.get_master_password()
        if existing_hash is not None:
            return

        print("Мастер-пароль не установлен. Создайте его сейчас.")
        while True:
            pwd1 = getpass.getpass("Новый мастер-пароль: ")
            pwd2 = getpass.getpass("Повторите мастер-пароль: ")
            if not pwd1:
                print("Пароль не может быть пустым.")
                continue
            if pwd1 != pwd2:
                print("Пароли не совпадают, попробуйте ещё раз.")
                continue
            break

        pwd_hash = self._hash_password(pwd1)
        self.db.set_master_password(pwd_hash)
        print("Мастер-пароль установлен.")

    def authenticate(self, attempts: int = 3) -> bool:
        """
        Аутентификация по мастер-паролю.
        Возвращает True, если пароль введён правильно, иначе False.
        """
        stored_hash = self.db.get_master_password()
        if stored_hash is None:
            # если БД пустая (теоретически), заставим задать пароль
            self.setup_master_password()
            stored_hash = self.db.get_master_password()

        for _ in range(attempts):
            pwd = getpass.getpass("Введите мастер-пароль: ")
            pwd_hash = self._hash_password(pwd)
            if pwd_hash == stored_hash:
                print("Аутентификация успешна.")
                return True
            else:
                print("Неверный пароль.")
        print("Слишком много неудачных попыток.")
        return False

    # ------------- генерация паролей -------------

    def generate_password(self, options: PasswordOptions) -> str:
        """
        Генерация случайного пароля по заданным параметрам.
        """
        import secrets

        char_set = ""
        if options.use_upper:
            char_set += string.ascii_uppercase
        if options.use_lower:
            char_set += string.ascii_lowercase
        if options.use_digits:
            char_set += string.digits
        if options.use_special:
            char_set += "!@#$%^&*()-_=+[]{};:,.<>?/"

        if not char_set:
            raise ValueError("Не выбрано ни одного типа символов для генерации пароля.")

        return "".join(secrets.choice(char_set) for _ in range(options.length))

    def generate_password_interactive(self) -> str:
        """
        Интерактивная генерация пароля с вопросами пользователю.
        """
        try:
            length_str = input("Длина пароля (по умолчанию 16): ").strip()
            length = int(length_str) if length_str else 16
        except ValueError:
            print("Некорректная длина, используется значение по умолчанию 16.")
            length = 16

        def ask_bool(prompt: str, default: bool = True) -> bool:
            suffix = "[Y/n]" if default else "[y/N]"
            ans = input(f"{prompt} {suffix}: ").strip().lower()
            if not ans:
                return default
            return ans in ("y", "yes", "д", "да")

        use_upper = ask_bool("Использовать заглавные буквы?", True)
        use_lower = ask_bool("Использовать строчные буквы?", True)
        use_digits = ask_bool("Использовать цифры?", True)
        use_special = ask_bool("Использовать спецсимволы?", True)

        options = PasswordOptions(
            length=length,
            use_upper=use_upper,
            use_lower=use_lower,
            use_digits=use_digits,
            use_special=use_special,
        )

        password = self.generate_password(options)
        print(f"Сгенерированный пароль: {password}")
        return password

    # ------------- операции с записями -------------

    def add_password(self, name: str, login: str, password: str, overwrite: bool = False) -> None:
        """
        Добавление новой записи.
        Если запись с таким name уже есть и overwrite=True — обновляет её.
        """
        encrypted = self.enc.encrypt(password)
        existing = self.db.get_password(name)

        if existing is None:
            self.db.add_password(name, login, encrypted)
            print(f"Запись '{name}' добавлена.")
        else:
            if overwrite:
                self.db.update_password(name, login, encrypted)
                print(f"Запись '{name}' обновлена.")
            else:
                print(f"Запись с названием '{name}' уже существует. Используйте overwrite=True или флаг CLI для обновления.")

    def get_password(self, name: str) -> None:
        """
        Получение и вывод пароля по названию.
        """
        row = self.db.get_password(name)
        if row is None:
            print(f"Запись '{name}' не найдена.")
            return
        decrypted = self.enc.decrypt(row["password_encrypted"])
        print(f"Название: {row['name']}")
        print(f"Логин:    {row['login']}")
        print(f"Пароль:   {decrypted}")

    def list_passwords(self) -> None:
        """
        Вывод списка всех записей (название + логин).
        """
        rows = self.db.list_passwords()
        if not rows:
            print("Нет сохранённых записей.")
            return
        print("Сохранённые записи:")
        for row in rows:
            print(f"- {row['name']}: {row['login']}")

    def delete_password(self, name: str) -> None:
        """
        Удаление записи по названию.
        """
        ok = self.db.delete_password(name)
        if ok:
            print(f"Запись '{name}' удалена.")
        else:
            print(f"Запись '{name}' не найдена.")

    # ------------- простое текстовое меню (по желанию) -------------

    def show_menu(self) -> None:
        """
        Небольшое текстовое меню (если захочешь запускать без argparse).
        Сейчас основной сценарий — через CLI в cli.py.
        """
        print("Меню команд:")
        print("1) add    - добавить запись")
        print("2) get    - получить пароль по названию")
        print("3) list   - показать все записи")
        print("4) delete - удалить запись")
        print("5) new    - сгенерировать пароль")
        print("0) exit   - выход")