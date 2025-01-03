import base64
import getpass
import hashlib
import inspect
import logging
import os
import pdb
import pickle
import re
from abc import ABC, abstractmethod
from copy import deepcopy
from pathlib import Path
from pprint import pprint

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BASE_DIR = Path(__file__).parent
HOME_DIR = BASE_DIR.joinpath(".PasswordManager")
FORMAT = "%(asctime)s %(levelname)s %(module)s %(funcName)s %(lineno)d %(message)s"
logging.basicConfig(
    filename=str(HOME_DIR.joinpath(".passwordmanager.log")),
    format=FORMAT,
)
logger = logging.getLogger("__name__")
logger.setLevel(logging.INFO)


def indexed_print(index, itemname):
    "Formats the single entry [row level] for text."
    print("{0:^8}".format(index), itemname)


def select_option(options, message, field_name):
    "For all the iterable items, this func provides pretty-printed output"
    print("{0:^8} {1:<30s}".format("Index", "Item Name"))
    print("{0:^8} {1:<30s}".format("-----", "---------"))
    for index, item in enumerate(options):
        indexed_print(index, item)
    user_choice = int(
        Interface().input(message=message, field_name=field_name, level=2)
    )
    return options[user_choice]


class AbstractInterface(ABC):
    """
    This class is Abstract to represent all the various interfaces that device
    can interact with this program.
    """

    @abstractmethod
    def input():
        """
        This method represents the input method for the interface to collect data.
        """
        pass


class TerminalInterface(AbstractInterface):
    @staticmethod
    def input(message="", kind="text", **kwargs):
        field = ""
        if kind == "text":
            field = input(message)
        elif kind == "password":
            field = getpass.getpass(message)
        else:
            print(f"kind {kind} for field: {field} is not supported. Check again.")
            return
        return field


class ScriptInterface(AbstractInterface):
    data = dict()

    @classmethod
    def input(cls, field_name="field_name", level=1, **kwargs):
        frames = inspect.getouterframes(inspect.currentframe())
        q_name = frames[level].frame.f_code.co_qualname
        field = cls.data[q_name].get(field_name, None)
        if field is None:
            print(f"Needed field {field_name} is not available in {q_name}.")
        return field

    def load(cls, user_data):
        cls.data.update(user_data)


class AutomationInterface(AbstractInterface):
    data = dict()

    @classmethod
    def input(cls, message="message", field_name="field_name", **kwargs):
        data = cls.data[field_name]
        cls.data.pop(field_name)
        return data

    def load(cls, user_data):
        cls.data.update(user_data)


class Interface:
    """
    This class is singleton of input interface for all user interaction with the
    program.
    """

    instance = None

    def __new__(cls):
        if cls.instance:
            return cls.instance

    @classmethod
    def update(cls, _type):
        cls.instance = _type()
        return cls.instance


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

    @staticmethod
    def initialize():
        algorithm = select_option(
            FernetwPassphrase.alg_opts,
            "Select the Algorithm for Encryption",
            "algorithm",
        )
        passphrase = Interface().input(
            message="Provide the passphrase:", field_name="passphrase"
        )
        iterations = int(
            Interface().input(
                message="Enter the number of iterations [Ideal 480000]:",
                field_name="iterations",
            )
        )
        iterations = iterations if iterations > 480000 else 480000
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
    This class is for mandatory encryption at Storage level for reading/writing action
    through this program.
    """

    def encryption_setup(self, op):
        passphrase = Interface().input(
            message=f"Enter the passphrase for File {op}",
            kind="password",
            field_name="passphrase",
        )
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
        except Exception:
            logger.error("Provided passphrase is incorrect")

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
        except Exception:
            logger.error("Decryption passphrase is incorrect")

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
    storage_opts = [File]
    encrypt_opts = [FernetwKey, FernetwPassphrase]

    def initialize(self):
        """
        This method is used to perform First-time setup of the config.
        """
        # just for internal reference
        self.name = Interface().input(
            message="Enter name of this Config:", field_name="name"
        )
        # for on disk name of file
        self.filename = Interface().input(
            message="Provide filename for this Config:", field_name="filename"
        )
        # to store on specific location on disk
        user_defined_path = Interface().input(
            message=f"Provide path to this file [Default: {HOME_DIR}]:[to store all the app related files.]",
            field_name="user_defined_path",
        )
        path = Path(user_defined_path) if user_defined_path else HOME_DIR
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
        self.path = path

        encrypt_opt = select_option(
            Config.encrypt_opts,
            "Select the Encrpytion option for the username and password:",
            "encrypt_opt",
        )
        self.encryption_type = encrypt_opt()

        self.encrypt_conf = encrypt_opt.initialize()

        storage_opt = select_option(
            Config.storage_opts,
            "Select the Storage option for the Config:",
            "storage_opt",
        )
        self.storage_type = storage_opt()

        self.data = dict()

        self.storage_type.post(self)
        logger.info("Config has been prepared")
        return self

    def pre_process(self):
        self.encryption_type.pre_process(self)

    def closing_time(self):
        """
        Allows to save the progress made with the Config session.
        """
        self.storage_type.post(self)

    def add_credentials(self):
        "Method to add the credential in the Config."
        domain = Interface().input(
            message="Enter the domain address:", field_name="domain"
        )
        username = Interface().input(
            message="Enter the login Username or Email:", field_name="username"
        )
        password = Interface().input(
            message="Enter the Password", kind="password", field_name="password"
        )
        if not self.data.get(domain, None):
            self.data[domain] = set()
        dmain = self.data[domain]
        dmain.add(self.encryption_type.encrypt(username, password))
        logger.info("domain, username and password added.")
        return {"username": username, "password": password, "domain": domain}

    def get_credentials(self):
        "To extract the credential information."
        keys = set()
        domain = Interface().input(message="Enter Domain:", field_name="domain")
        for key in self.data.keys():
            if key is None:
                continue
            if key.find(domain) >= 0:
                keys.add(key)
        output = {}
        for d in keys:
            for instance in self.data[d]:
                if not output.get(d, None):
                    output[d] = []
                output[d].append(self.encryption_type.decrypt(instance))
            logger.info("Retrieving domain, username and password")
        return output

    def delete_credentials(self):
        "Deletes all username/password for the provided Domain"
        domain = Interface().input(field_name="domain", message="Domain:")
        if not self.data.get(domain, None):
            print(f"No data found for {domain}!")
            return
        for inst in self.data[domain]:
            self.data.pop(domain)
            print(f"Deleted data for {domain}")
            logger.info("Deleted all username and password for domain")
        return {"domain": domain}

    def delete_instance(self):
        "Deletes only domain and username matching username/password data."
        domain = Interface().input(field_name="domain", message="Domain:")
        username = Interface().input(field_name="username", message="Username:")
        temp = deepcopy(self.data.get(domain, None))
        if not bool(temp):
            print(f"No instance for {domain} with {username} found!")
            return
        for inst in temp:
            if (
                username
                == self.encryption_type.f.decrypt(inst.username.encode()).decode()
            ):
                self.data[domain].remove(inst)
                print(f"Deleted {username} for {domain}.")
                logger.info(
                    "Deleted username and password entry for domain and username"
                )
        return {"domain": domain, "username": username}


class App:
    def __init__(self):
        self.config = None

    def _get_conf_files(self):
        if not Path(HOME_DIR).exists():
            Path(HOME_DIR).mkdir(parents=True)
        pth = Path(HOME_DIR)
        prob_configs = []
        for file_ in pth.iterdir():
            if file_.is_file() and not file_.name.startswith("."):
                prob_configs.append(file_)
        if len(prob_configs) == 0:
            print(
                f" [ERROR] We did not find any userdata at {HOME_DIR}. Make sure file",
                "and folders are at place.",
            )
        return prob_configs

    def load_config(self):
        """
        This methods checks some preliminary condition and initializes the app class.
        """
        prob_configs = self._get_conf_files()
        conf = select_option(prob_configs, "Select the config file:", "probe_config")
        try:
            self.config = File().get(conf)
            self.config.pre_process()
            logger.info("Loaded the config data")
            return self.config
        except Exception as e:
            print("[ERROR]", e)
            logger.info(e)


class InputHelper:
    klass_list = [App, Config, FernetwPassphrase, Storage]

    @classmethod
    def get_input_params(cls):
        """
        This method helps to create JSON/Dict object to pass value for other Interface.
        """
        data = dict()
        for _class in cls.klass_list:
            for _klass_method in inspect.getmembers(
                _class, predicate=inspect.isfunction
            ):
                _method = getattr(_class, _klass_method[0], None)
                _code = inspect.getsource(_method)

                _interface_args = re.findall(
                    r'Interface\([\b]*\)\.input\([\b]*([\w=\[\]:,\{\}_.\n" ]*)\)', _code
                )
                qual_name = _method.__qualname__
                if bool(_interface_args):
                    data[qual_name] = dict()
                    for _interface_arg in _interface_args:
                        for _kw_pairs in _interface_arg.split(","):
                            _kw = _kw_pairs.strip().split("=")
                            if "field_name" in _kw:
                                _field_name = _kw[1].replace('"', "")
                                data[qual_name][_field_name] = ""

                _temp = re.findall(
                    r'select_option\([\b]*([\w=\[\]:,\{\}_.\n" ]*)\)', _code
                )
                if bool(_temp):
                    if data.get(qual_name, None) is None:
                        data[qual_name] = dict()
                    for _select_option_args in _temp:
                        data[qual_name][
                            _select_option_args.split(",")[2].strip().replace('"', "")
                        ] = ""

        pprint(data, indent=4)
        return data
