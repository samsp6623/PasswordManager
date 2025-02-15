import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from core import (
    App,
    Config,
    FernetwPassphrase,
    # InputHelper,
    Interface,
    ScriptInterface,
)


def get_path_reducer(path):
    if "App.load_config" in path:
        return App._get_conf_files()
    elif "Config.initialize" in path:
        return [
            [i.__name__ for i in Config.storage_opts],
            [i.__name__ for i in Config.encrypt_opts],
        ]
    elif "FernetwPassphrase.initialize" in path:
        return [i.name for i in FernetwPassphrase.alg_opts]


def post_path_reducer(path, data):
    app = App()
    Interface.update(ScriptInterface)
    Interface().load(data)
    if "conf-initialize" in path:
        try:
            Config().initialize()
            return {"message": "Successfully created Config"}
        except Exception as e:
            return {"message": e.args}
    conf = app.load_config()
    if "add-credential" in path:
        output = conf.add_credentials()
        conf.closing_time()
        return output
    elif "get-credentials" in path:
        output = conf.get_credentials()
        return output
    elif "delete-credential" in path:
        output = conf.delete_credentials()
        conf.closing_time()
        return output
    elif "delete-instance" in path:
        output = conf.delete_instance()
        conf.closing_time()
        return output


class HTTPHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header(
            "Access-Control-Allow-Origin",
            "*",
        )
        self.send_header(
            "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"
        )
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Type", "application/json")
        super().end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        data = get_path_reducer(self.path)
        self.wfile.write(json.dumps(data).encode())

    def do_POST(self):
        output = ""
        cl = int(self.headers["Content-Length"])
        body = self.rfile.read(cl)
        self.send_response(200)
        self.end_headers()
        data = json.loads(body.decode())
        try:
            output = post_path_reducer(self.path, data)
        except Exception as e:
            print("ERROR!!", e)
            output = {"message": "Please check inputted credentials."}
        self.wfile.write(json.dumps(output).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()


def run(server_class=HTTPServer, handler_class=HTTPHandler):
    server_address = ("localhost", 8000)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()


if __name__ == "__main__":
    run()
