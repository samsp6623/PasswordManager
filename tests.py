from core import HOME_DIR, App, Config, Interface, ScriptInterface

data_dict = dict()

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
data_dict.update({"App.load_config": {"probe_config": 0}})
data_dict.update(
    {
        "Config.add_credentials": {
            "domain": "example.com",
            "password": "user",
            "username": "user",
            "notes": "HELLO WORLD",
            "otp": "SOMESECRET",
        }
    }
)
data_dict.update({"Config.get_credentials": {"domain": "example.com"}})
data_dict.update(
    {
        "Config.update_credentials": {
            "old_record": 0,
            "new_username": "USERS",
            "new_password": "PASSWORD",
            "notes": "hello world",
            "otp": "somesecret",
        }
    }
)
data_dict.update({"Config.delete_credentials": {"domain": "example.com"}})
data_dict.update(
    {"Config.delete_instance": {"domain": "example.com", "username": "user"}}
)

if __name__ == "__main__":
    Interface.update(ScriptInterface)
    Interface().load(data_dict)
    conf = Config().initialize()
    app = App()
    app.load_config()
    data_dict.pop("App.load_config")
    data_dict.pop("Storage.encryption_setup")
    app.config.add_credentials()
    app.config.get_credentials()
    app.config.update_credentials()

    del data_dict["Config.add_credentials"]
    data_dict.update(
        {
            "Config.add_credentials": {
                "domain": "exa.com",
                "password": "example",
                "username": "example",
                "notes": "viola",
                "otp": "someotpsecret",
            }
        }
    )
    data_dict.update({"Config.get_credentials": {"domain": "apple.com"}})
    Interface().load(data_dict)

    app.config.add_credentials()
    app.config.get_credentials()
    # app.config.delete_credentials()
    # app.config.delete_instance()
    app.config.closing_time()
