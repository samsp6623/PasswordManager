import cmd
import os
import pdb

from core import App, Config
from utils import generate_random_password


class TurtleShell(cmd.Cmd):
    intro = """Welcome to the Password Manager, Powered by turtle shell.
    Type help or ? to list commands. pass arg"""
    prompt = "(password-manager) "
    file = None

    def do_make_config(self, arg):
        "This one helps to initialize new Config file."
        Config().initialize()

    def do_load_config(self, arg):
        "This one helps to load existing Config file"
        self.config = App().load_config()

    def do_change_setup(self, arg):
        """
        This option helps to reconfigure(migrate) existing data to with newer
        configuration.
        """
        if not self.config:
            print("Please load your configuration first.")
        conf = Config().initialize()
        conf.pre_process()
        setattr(conf, "is_test", True)
        for d, ups in self.config.data.items():
            for up in ups:
                data = self.config.encryption_type.decrypt(up)
                conf.add_credentials(domain=d, **data)
        setattr(conf, "is_test", False)
        conf.storage_type.post(conf)
        print("Successfully changed the algorithm setup for data encryption.")

    def do_add_cred(self, arg):
        "Prompts to add the username and password for the domain."
        try:
            self.config.add_credentials()
        except Exception as e:
            print("Error!", e)

    def do_get_creds(self, arg):
        "Lists decrypted username/password pairs for provided domain."
        try:
            domain = arg.split(" ")[0]
            print(self.config.get_credentials(domain))
        except KeyError:
            print("Please provide the domain name.")

    def do_delete_creds(self, arg):
        "Removes all the username/password entry for provided domain."
        try:
            domain = arg.split(" ")
            self.config.delete_credentials(domain)
        except KeyError:
            print("Provide name of domain")

    def do_delete_instance(self, arg):
        "Deletes one entry on the username/password where match is found."
        try:
            data = arg.split(" ")
            domain = data[0]
            username = data[1]
            self.config.delete_instance(domain, username)
        except KeyError:
            print("Make sure to provide name of domain")

    def do_suggest_password(self, arg):
        """Creates the password, can also be passed with arg to for more customization
        like `suggest_password 12 special digits`"""
        try:
            size = int(arg.split(" ")[0])
        except Exception:
            size = 0
        length = size if size > 7 else 12
        print(generate_random_password(length=length))

    def do_introspect(self, arg):
        "For developer only, Allows to introspect in the objects in the runtime"
        pdb.set_trace()

    def do_save(self, arg):
        self.config.closing_time()
        print("[SUCCESS] all changes are saved.")

    def do_finish(self, arg):
        "Stop recording, close the turtle window, and exit:  BYE"
        print("All done. Thanks for using password Manager.")
        return True


if __name__ == "__main__":
    TurtleShell().cmdloop()
