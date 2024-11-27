import random
import string


def indexed_print(index, itemname):
    "Formats the single entry [row level] for text."
    print("{0:^8}".format(index), itemname)


def select_option(options, message):
    "For all the iterable items, this func provides pretty-printed output"
    print("{0:^8} {1:<30s}".format("Index", "Item Name"))
    print("{0:^8} {1:<30s}".format("-----", "---------"))
    for index, item in enumerate(options):
        indexed_print(index, item)
    user_choice = int(input(message))
    return options[user_choice]


def generate_random_password(length=25):
    """
    Creates password with some customization, like `digit`, `special` and
    number to state the length of the password.
    """
    char_pool = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    passphrase = "".join(random.choices(char_pool, k=length))
    return passphrase
