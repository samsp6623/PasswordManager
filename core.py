import base64
import getpass
import hashlib
import logging
import os
import pdb
import pickle
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils import select_option

home_dir = os.environ.get("MY_PASSWORDMANAGER_FILEPATH", None)
HOME_DIR = (
    Path(home_dir) if home_dir else Path("/Users/hakunamatata/Public/.PasswordManager")
)

FORMAT = "%(asctime)s %(levelname)s %(module)s %(funcName)s %(lineno)d %(message)s"
logging.basicConfig(
    filename="/Users/hakunamatata/Documents/Projects/PasswordManager/passwordmanager.log",
    format=FORMAT,
)
logger = logging.getLogger("__name__")
logger.setLevel(logging.INFO)


class AbstractEncryptionClass(ABC):
    """
    This class stores and provides method to encrypt/decrypt the plain text.
    This is used for the username/password or any information that needs to be
    encrypted.
    """

    @abstractmethod
    def initialize():
        """
        This method is used to perform First Time setup.
        It helps with setting up various conf values to perform necessary job.
        """

    @abstractmethod
    def pre_process():
        """
        This method uses all the stored conf data and prepares the general
        setup to perform necessary further action.
        """

    def encrypt(self, username, password):
        username = self.f.encrypt(username.encode()).decode()
        password = self.f.encrypt(password.encode()).decode()
        logger.info("Ecrypted username and password")
        return Entries(username, password)

    def decrypt(self, inst):
        username = self.f.decrypt(inst.username.encode())
        password = self.f.decrypt(inst.password.encode())
        logger.info("Decrypted username and password")
        return {
            "username": username.decode(),
            "password": password.decode(),
        }

    def __str__(self):
        return self.__class__.__name__


class FernetwKey(AbstractEncryptionClass):
    def initialize():
        key_dict = {"key": Fernet.generate_key()}
        logger.info("Generated key for FernetwKey.")
        logger.debug("Generated key for FernetwKey. %s", str(key_dict["key"]))
        return key_dict

    def pre_process(self, conf):
        self.f = Fernet(conf.encrypt_conf["key"])


class FernetwPassphrase(AbstractEncryptionClass):
    alg_opts = [
        hashes.SHA1,
        hashes.SHA224,
        hashes.SHA256,
        hashes.SHA384,
        hashes.SHA512,
        hashes.SHA512_224,
        hashes.SHA512_256,
        hashes.SHA3_224,
        hashes.SHA3_256,
        hashes.SHA3_384,
        hashes.SHA3_512,
        hashes.SM3,
        hashes.MD5,
    ]

    def initialize():
        algorithm = select_option(
            FernetwPassphrase.alg_opts, "Select the Algorithm for Encryption"
        )
        passphrase = getpass.getpass("Provide the passphrase:")
        iterations = input("Enter the number of iterations [Ideal 480000]:")
        iterations = (
            iterations if iterations.isdigit() and iterations > 480000 else 480000
        )
        salt = os.urandom(16)
        conf_data = {
            "algorithm": algorithm(),
            "passphrase": passphrase,
            "length": 32,
            "iterations": iterations,
            "salt": salt,
        }
        logger.info("Conf data prepared")
        logger.debug(
            "Configure data is algorithm is: %s %s %s %s %s",
            conf_data["algorithm"],
            conf_data["passphrase"],
            conf_data["length"],
            conf_data["iterations"],
            conf_data["salt"],
        )
        return conf_data

    def pre_process(self, conf):
        try:
            algorithm = conf.encrypt_conf["algorithm"]
            passphrase = conf.encrypt_conf["passphrase"]
            length = conf.encrypt_conf["length"]
            iterations = conf.encrypt_conf["iterations"]
            salt = conf.encrypt_conf["salt"]
        except KeyError:
            logger.error("Encryption config data missing.")
            raise Exception(
                "Some propeties are not well defined. File might be corrupt."
            )
        kdf = PBKDF2HMAC(algorithm, length, salt, iterations)
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        self.f = Fernet(key)
        logger.debug(
            "Pre-process conf is: %s %s %s %s %s",
            getattr(conf.encrypt_conf["algorithm"], __name__, None)
            or getattr(conf.encrypt_conf["algorithm"], "name", None),
            conf.encrypt_conf["passphrase"],
            conf.encrypt_conf["length"],
            conf.encrypt_conf["iterations"],
            conf.encrypt_conf["salt"],
        )


class Storage(ABC):
    """
    This class is all about the accessing of storage volume with encryption.
    """

    def encryption_setup(self, message):
        passphrase = getpass.getpass(f"Enter the passphrase for File {message}")
        salt = hashlib.sha256(os.environ.get("SALT").encode("utf-8")).digest()
        kdf = PBKDF2HMAC(hashes.SHA512(), 32, salt, 500000)
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        key = Fernet(key)
        logger.info("Prepared Fernet key for storage")
        logger.debug(
            "Storage configuration data is, %s %s %s %s",
            passphrase,
            salt,
            key._signing_key,
            key._encryption_key,
        )
        return key

    def file_encryption(self, data):
        f = self.encryption_setup("Encryption")
        try:
            output = f.encrypt(data)
            logger.info("File data encrypted")
            return output
        except InvalidToken:
            logger.error("InvalidToken raised during encryption")
            print("[ERROR] Provided passphrase is incorrect.")
        except Exception:
            logger.error("Provided passphrase is incorrect")
            print("[ERROR] Something went wrong. Contact Developer")

    def file_decryption(self, data):
        f = self.encryption_setup("Decryption")
        try:
            output = f.decrypt(data)
            logger.info("File data decrypted")
            logger.debug(
                "File decryption key is: %s %s",
                str(f._signing_key),
                str(f._encryption_key),
            )
            return output
        except InvalidToken as e:
            logger.error("InvalidToken raised during decryption")
            print("[ERROR] Provided passphrase is incorrect.", e)
        except Exception:
            logger.error("Decryption passphrase is incorrect")
            print("[ERROR] Something went wrong. Contact Developer")

    def __str__(self):
        return self.__class__.__name__


class File(Storage):
    """
    This class is used to read the config file that chooses to store the data on
    local machine `File` system, as well for any cloud storage as for program to start
    it needs some intial data.
    """

    def get(self, file):
        "Takes encrypted file object and returns the python config object."
        config = pickle.loads(self.file_decryption(file.read_bytes()))
        logger.info("File Storage data retrieved.")
        logger.debug("File conf is: %s", config.__dict__)
        return config

    def post(self, conf):
        "Takes python config object and writes the encrypted pickle data."
        if not Path(HOME_DIR.joinpath(conf.name)).exists():
            Path(HOME_DIR.joinpath(conf.name)).touch()
        with open(HOME_DIR.joinpath(conf.name), mode="wb") as file:
            file.write(self.file_encryption(pickle.dumps(conf)))
        logger.info("File Storage data written.")
        logger.debug("File conf is: %s", conf.__dict__)

    def delete(self, conf):
        "Deletes the config file"
        os.remove(HOME_DIR + "/" + conf.name)
        print("File has been deleted.")
        logger.info("File Storage deleted from disk.")


class Entries:
    def __init__(self, username, password) -> None:
        self.username = username
        self.password = password

    def __eq__(self, other):
        if (self.username == other.username) and (self.password == other.password):
            return True
        return False

    def __hash__(self):
        return hash((self.username, self.password))

    def __str__(self):
        return "username: " + self.username + " password: " + self.password

    def __repr__(self):
        return (
            "<class Entries: Username: "
            + self.username
            + ", Password: "
            + self.password
            + " >"
        )


class Config:
    def initialize(self):
        """
        This method is used to perform First-time setup of the config.
        """
        # just for internal reference
        self.name = input("Enter name of this Config:")
        # for on disk name of file
        self.filename = input("Provide filename for this Config:")
        # to store on specific location on disk
        user_defined_path = input(
            f"Provide path to this file [Default: {HOME_DIR}]:[to store all the app related files.]"
        )
        path = Path(user_defined_path) if user_defined_path else HOME_DIR
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
        self.path = path
        encrypt_opts = [FernetwKey, FernetwPassphrase]
        encrypt_opt = select_option(
            encrypt_opts, "Select the Encrpytion option for the username and password:"
        )
        self.encryption_type = encrypt_opt()
        self.encrypt_conf = encrypt_opt.initialize()
        storage_opts = [File]
        storage_opt = select_option(
            storage_opts, "Select the Storage option for the Config:"
        )
        self.storage_type = storage_opt()
        self.data = dict()

        File().post(self)
        logger.info("Config has been prepared")
        return self

    def pre_process(self):
        self.encryption_type.pre_process(self)

    def closing_time(self):
        """
        Allows to save the progress made with the Config session.
        """
        self.storage_type.post(self)

    def add_credentials(self, domain=None, username=None, password=None, test=False):
        "Method to add the credential in the Config."
        if test:
            domain = domain
            username = username
            password = password
        else:
            domain = input("Enter the domain address:")
            username = input("Enter the login Username or Email:")
            password = getpass.getpass("Enter the Password")
        if self.data.get(domain, None):
            dmain = self.data[domain]
        else:
            self.data[domain] = set()
            dmain = self.data[domain]
        dmain.add(self.encryption_type.encrypt(username, password))
        logger.info("domain, username and password added.")

    def get_credentials(self, domain):
        "To extract the credential information."
        keys = []
        for key in self.data.keys():
            if key is None:
                continue
            if key.find(domain) != -1:
                keys.append(key)
        output = {}
        for d in keys:
            for instance in self.data[d]:
                output.update({d: self.encryption_type.decrypt(instance)})
            logger.info("Retrieving domain, username and password")
        return output

    def delete_credentials(self, domain):
        "Deletes all username/password for the provided Domain"
        for inst in self.data[domain]:
            del inst
        logger.info("Deleted all username and password for domain")

    def delete_instance(self, domain, username):
        "Deletes only domain and username matching username/password data."
        for inst in self.data[domain]:
            if inst.username == username:
                del inst
        logger.info("Deleted username and password entry for domain and username")


class App:
    def __init__(self):
        self.config = None

    def load_config(self):
        """
        This methods checks some preliminary condition and initializes the app class.
        """
        if not Path(HOME_DIR).exists():
            Path(HOME_DIR).mkdir(parents=True)
        pth = Path(HOME_DIR)
        prob_configs = []
        for file_ in pth.iterdir():
            if file_.is_file():
                prob_configs.append(file_)
        if len(prob_configs) == 0:
            print(
                f" [ERROR] We did not find any userdata at {HOME_DIR}. Make sure file",
                "and folders are at place.",
            )
        conf = select_option(prob_configs, "Select the config file:")
        try:
            self.config = File().get(conf)
            self.config.pre_process()
            logger.info("Loaded the config data")
            return self.config
        except IndexError:
            print("[ERROR] Provided value is out of range.")
            logger.info("Value out of range")
        except ValueError:
            print("[ERROR] Provided value is not integer number. Try again.")
            logger.info("Value out of range")
        except Exception:
            print("[ERROR] Technical Error.")
            logger.info("Technical Error.")
