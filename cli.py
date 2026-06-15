import argparse
import getpass
import sys

from password_manager import PasswordGenerator, PasswordOptions


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Создаёт парсер командной строки с подкомандами.
    """
    parser = argparse.ArgumentParser(
        description="Простой CLI-менеджер паролей с шифрованием (Fernet + SQLite3)."
    )

    subparsers = parser.add_subparsers(dest="command", help="Команда")

    # add
    add_parser = subparsers.add_parser("add", help="Добавить новую запись")
    add_parser.add_argument("name", help="Название/откуда (например, 'Google')")
    add_parser.add_argument("login", help="Логин")
    add_parser.add_argument(
        "-p",
        "--password",
        help="Пароль (если не указан, будет запрошен интерактивно)",
    )
    add_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Обновить запись, если она уже существует",
    )

    # get
    get_parser = subparsers.add_parser("get", help="Получить пароль по названию")
    get_parser.add_argument("name", help="Название записи")

    # list
    subparsers.add_parser("list", help="Показать список всех записей")

    # delete
    delete_parser = subparsers.add_parser("delete", help="Удалить запись по названию")
    delete_parser.add_argument("name", help="Название записи")

    # new (генерация пароля)
    new_parser = subparsers.add_parser("new", help="Создать новый пароль")
    new_parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=16,
        help="Длина пароля (по умолчанию 16)",
    )
    new_parser.add_argument(
        "--no-upper",
        action="store_true",
        help="Не использовать заглавные буквы",
    )
    new_parser.add_argument(
        "--no-lower",
        action="store_true",
        help="Не использовать строчные буквы",
    )
    new_parser.add_argument(
        "--no-digits",
        action="store_true",
        help="Не использовать цифры",
    )
    new_parser.add_argument(
        "--no-special",
        action="store_true",
        help="Не использовать спецсимволы",
    )

    return parser


def main():
    """
    Основная точка входа CLI.
    """
    manager = PasswordGenerator()

    # Сначала убедимся, что мастер-пароль существует
    manager.setup_master_password()

    parser = build_arg_parser()
    args = parser.parse_args()

    # Если команду не передали — покажем help и выйдем
    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Аутентификация перед выполнением команд
    if not manager.authenticate():
        sys.exit(1)

    # Обработка команд
    if args.command == "add":
        if args.password:
            password = args.password
        else:
            pwd1 = getpass.getpass("Пароль: ")
            pwd2 = getpass.getpass("Повторите пароль: ")
            if pwd1 != pwd2:
                print("Пароли не совпадают.")
                sys.exit(1)
            password = pwd1

        manager.add_password(
            name=args.name,
            login=args.login,
            password=password,
            overwrite=args.overwrite,
        )

    elif args.command == "get":
        manager.get_password(args.name)

    elif args.command == "list":
        manager.list_passwords()

    elif args.command == "delete":
        manager.delete_password(args.name)

    elif args.command == "new":
        options = PasswordOptions(
            length=args.length,
            use_upper=not args.no_upper,
            use_lower=not args.no_lower,
            use_digits=not args.no_digits,
            use_special=not args.no_special,
        )
        pwd = manager.generate_password(options)
        print(f"Новый пароль: {pwd}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()