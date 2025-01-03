from core import HOME_DIR, App, Interface, ScriptInterface

data_dict = dict()

data_dict.update(
    {
        "Config.add_credentials": {
            "domain": "example.com",
            "password": "user",
            "username": "user",
        }
    }
)
data_dict.update({"Config.delete_credentials": {"domain": "example.com"}})
data_dict.update(
    {"Config.delete_instance": {"domain": "example.com", "username": "user"}}
)
data_dict.update({"Config.get_credentials": {"domain": "example.com"}})
data_dict.update(
    {
        "Config.initialize": {
            "encrypt_opt": 1,
            "filename": "test_sha1",
            "name": "test_sha1",
            "storage_opt": 0,
            "user_defined_path": HOME_DIR,
        }
    }
)
data_dict.update(
    {
        "FernetwPassphrase.initialize": {
            "algorithm": 0,
            "iterations": 480000,
            "passphrase": "userpassword",
        }
    }
)
data_dict.update({"Storage.encryption_setup": {"passphrase": "userpassword"}})

if __name__ == "__main__":
    Interface.update(ScriptInterface)
    Interface().load(data_dict)
    # conf = Config().initialize()
    app = App()
    app.load_config()
    app.config.add_credentials()
    app.config.get_credentials()
    # app.config.delete_credentials()
    # app.config.delete_instance()
