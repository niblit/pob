from base64 import b64decode, b64encode
from os import urandom
from typing import Union, Tuple


def main():
    option, data = tui()
    if option == 1:
        key = get_key(len(data))

        ciphertext = cover(data, key)

        print(f"{ciphertext}.{key}")
    elif option == 2:
        if data.count('.') != 1:
            print("Invalid data")
            raise SystemExit

        ciphertext, key = data.split('.')

        if len(ciphertext) < len(key):
            print("Invalid data")
            raise SystemExit

        data = reveal(ciphertext, key)
        print(f"{data}")


def tui() -> Tuple[int, str]:
    print("Password Obfuscation tool by niblit!")
    print("Please select an option:")
    print("  1) Obfuscate a password")
    print("  2) Reveal a password")
    while True:
        try:
            option = int(input("> ").strip())
            if option in {1, 2}:
                break
            else:
                print("Enter [1] or [2]")
                continue
        except ValueError:
            print("Enter a number")
            continue
        except (KeyboardInterrupt, EOFError):
            print()
            raise SystemExit
    data = input("Enter your data: ")
    return option, data


def get_key(size: int) -> str:
    return encode(
        urandom(
            size
        )
    )[:size]


def encode(data: Union[str, bytes]) -> str:
    return b64encode(
        data.encode()
        if isinstance(data, str)
        else
        data
        if isinstance(data, bytes)
        else
        b''
    ).decode()


def decode(data: Union[str, bytes]) -> str:
    return b64decode(
        data.encode()
        if isinstance(data, str)
        else
        data
        if isinstance(data, bytes)
        else
        b''
    ).decode()


def cover(data: str, key: str) -> str:
    return encode(
        b"".join(
            (
                chr(
                    ord(a) ^ ord(b)
                ).encode()
                for a, b in zip(data, key)
            )
        )
    )


def reveal(data: str, key: str) -> str:
    return "".join(
        (
    chr(
                ord(a) ^ ord(b)
            )
            for a, b in zip(decode(data), key)
        )
    )


if __name__ == '__main__':
    main()
