import tkinter as tk
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import threading

# Sample Credentials
USERNAME = "admin"
PASSWORD = "admin"

class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)

        if "Authorization" not in self.headers:
            self.send_auth_required_response()
            return

        auth_header = self.headers["Authorization"]
        if not self.is_authenticated(auth_header):
            self.send_auth_required_response()
            return

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(bytes("Hello, authenticated user!", "utf-8"))

    def is_authenticated(self, auth_header):
        auth_type, auth_value = auth_header.split(' ', 1)
        if auth_type.lower() != 'basic':
            return False
        credentials = base64.b64decode(auth_value).decode("utf-8")
        username, password = credentials.split(':', 1)
        return username == USERNAME and password == PASSWORD

    def send_auth_required_response(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Secure Area"')
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(bytes("Authentication required.", "utf-8"))

def run(server_class=HTTPServer, handler_class=MyHTTPRequestHandler, port=5050):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting HTTP server on port {port}...")
    httpd.serve_forever()

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HTTP Server")

        self.start_button = tk.Button(root, text="Start Server", command=self.start_server)
        self.start_button.pack(pady=10)

    def start_server(self):
        self.start_button.config(state=tk.DISABLED)
        thread = threading.Thread(target=run)
        thread.start()

def main():
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
