import sqlite3
from typing import Optional, List
class DatabaseManager:
    """
    Отвечает за взаимодействие с базой данных.

    Таблицы:
    - master_password (id INTEGER PRIMARY KEY, password_hash TEXT NOT NULL)
    - passwords (id INTEGER PRIMARY KEY, name TEXT UNIQUE, login TEXT, password_encrypted BLOB)
    """

    def __init__(self, db_path: str = "passwords.db"):
        """
        В конструкторе создаётся подключение к SQLite и инициализируются таблицы.
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.init_database()

    def init_database(self) -> None:
        """
        Инициализирует таблицы, если их еще нет.
        Есть отдельная таблица для мастер-пароля.
        """
        cur = self.conn.cursor()

        # Таблица для мастер-пароля (одна строка: id = 1)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL
            )
            """
        )

        # Таблица для паролей
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                login TEXT NOT NULL,
                password_encrypted BLOB NOT NULL
            )
            """
        )

        self.conn.commit()

    # ------------- мастер-пароль -------------

    def set_master_password(self, password_hash: str) -> None:
        """
        Установка (или переустановка) мастер-пароля.
        Принимает уже посчитанный SHA-256 хэш.
        """
        cur = self.conn.cursor()
        # гарантируем одну запись с id = 1
        cur.execute("DELETE FROM master_password")
        cur.execute(
            "INSERT INTO master_password (id, password_hash) VALUES (1, ?)",
            (password_hash,),
        )
        self.conn.commit()

    def get_master_password(self) -> Optional[str]:
        """
        Возвращает хэш мастер-пароля или None, если он еще не установлен.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT password_hash FROM master_password WHERE id = 1")
        row = cur.fetchone()
        if row is None:
            return None
        return row["password_hash"]

    # ------------- операции с паролями -------------

    def add_password(self, name: str, login: str, password_encrypted: bytes) -> None:
        """
        Добавление новой записи (название, логин, зашифрованный пароль).
        """
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO passwords (name, login, password_encrypted)
            VALUES (?, ?, ?)
            """,
            (name, login, password_encrypted),
        )
        self.conn.commit()

    def update_password(self, name: str, login: str, password_encrypted: bytes) -> None:
        """
        Обновление записи по названию (если уже существует).
        """
        cur = self.conn.cursor()
        cur.execute(
            """
            UPDATE passwords
            SET login = ?, password_encrypted = ?
            WHERE name = ?
            """,
            (login, password_encrypted, name),
        )
        self.conn.commit()

    def get_password(self, name: str) -> Optional[sqlite3.Row]:
        """
        Получение записи по названию.
        Возвращает sqlite3.Row или None.
        """
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT id, name, login, password_encrypted
            FROM passwords
            WHERE name = ?
            """,
            (name,),
        )
        row = cur.fetchone()
        return row

    def list_passwords(self) -> List[sqlite3.Row]:
        """
        Возвращает список всех записей (id, name, login).
        """
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT id, name, login
            FROM passwords
            ORDER BY name
            """
        )
        rows = cur.fetchall()
        return rows

    def delete_password(self, name: str) -> bool:
        """
        Удаление записи по названию.
        Возвращает True, если запись была удалена.
        """
        cur = self.conn.cursor()
        cur.execute("DELETE FROM passwords WHERE name = ?", (name,))
        self.conn.commit()
        return cur.rowcount > 0

    def close(self) -> None:
        """
        Закрытие соединения с базой.
        """
        self.conn.close()