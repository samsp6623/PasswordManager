import cmd
import pdb

from core import App, AutomationInterface, Config, Interface, TerminalInterface
from utils import generate_random_password


class TurtleShell(cmd.Cmd):
    intro = """Welcome to the Password Manager, Powered by turtle shell.
    Type help or ? to list commands. pass arg"""
    prompt = "(password-manager) "
    file = None

    def do_load_config(self, arg):
        "This one helps to load existing Config file"
        try:
            app = App()
            Interface.update(TerminalInterface)
            self.context = app.load_config()
        except Exception as e:
            print("Cant load file, try again:", e)

    def do_make_config(self, arg):
        "This one helps to initialize new Config file."
        Config().initialize()

    def do_change_setup(self, arg):
        """
        This option helps to reconfigure(migrate) existing data to with newer
        configuration.
        """
        if not self.context:
            print("Please load your configuration first.")
        conf = Config().initialize()
        Interface.update(AutomationInterface)
        conf.pre_process()
        for d, ups in self.context.data.items():
            for up in ups:
                data = self.context.encryption_type.decrypt(up)
                Interface().load(data)
                conf.add_credentials()
        Interface.update(TerminalInterface)
        conf.storage_type.post(conf)
        print("Successfully changed the algorithm setup for data encryption.")

    def do_add_cred(self, arg):
        "Prompts to add the username and password for the domain."
        try:
            self.context.add_credentials()
        except Exception as e:
            print("Error!", e)

    def do_get_creds(self, arg):
        "Lists decrypted username/password pairs for provided domain."
        try:
            print(self.context.get_credentials())
        except KeyError:
            print("Please provide the domain name.")

    def do_delete_creds(self, arg):
        "Removes all the username/password entry for provided domain."
        self.context.delete_credentials()

    def do_delete_instance(self, arg):
        "Deletes one entry on the username/password where match is found."
        self.context.delete_instance()

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
        self.context.closing_time()
        print("[SUCCESS] all changes are saved.")

    def do_finish(self, arg):
        "Stop recording, close the turtle window, and exit:  BYE"
        print("All done. Thanks for using password Manager.")
        return True


if __name__ == "__main__":
    TurtleShell().cmdloop()
