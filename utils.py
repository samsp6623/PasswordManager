import random


def generate_random_password(length=25):
    """
    Creates password with some customization, like `digit`, `special` and
    number to state the length of the password.
    """
    char_pool = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'\
        ()*+,-./:;<=>?@[\\]^_`{|}~"
    passphrase = "".join(random.choices(char_pool, k=length))
    return passphrase
