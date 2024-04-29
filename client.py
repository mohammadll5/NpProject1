import tkinter as tk #ui
from tkinter import ttk
from tkinter import messagebox
import requests
from requests.auth import HTTPBasicAuth

class RequestApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HTTP Requester")

        # Application Login UI Components
        self.login_label = ttk.Label(root, text="Enter credentials to access methods")
        self.login_label.grid(row=0, column=0, columnspan=2, pady=5, sticky="w")

        self.username_label = ttk.Label(root, text="Username:")
        self.username_label.grid(row=1, column=0, pady=5, sticky="w")
        self.username_entry = ttk.Entry(root, width=50)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5, sticky="we")

        self.password_label = ttk.Label(root, text="Password:")
        self.password_label.grid(row=2, column=0, pady=5, sticky="w")
        self.password_entry = ttk.Entry(root, width=50, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5, sticky="we")

        self.login_button = ttk.Button(root, text="Login", command=self.verify_credentials)
        self.login_button.grid(row=3, column=1, padx=5, pady=5, sticky="e")

    def setup_request_ui(self):
        # URL Entry
        self.url_label = ttk.Label(self.root, text="Server URL:")
        self.url_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.url_entry = ttk.Entry(self.root, width=50)
        self.url_entry.grid(row=4, column=1, columnspan=2, padx=5, pady=5, sticky="we")
        self.url_entry.insert(tk.END, "http://localhost:5050/")  # Default server URL

        # Method Selector
        self.method_label = ttk.Label(self.root, text="Method:")
        self.method_label.grid(row=5, column=0, padx=5, pady=5, sticky="w")
        self.method_combobox = ttk.Combobox(self.root, values=["GET", "POST", "PUT", "DELETE"])
        self.method_combobox.current(0)
        self.method_combobox.grid(row=5, column=1, padx=5, pady=5, sticky="we")

        # Cookies Management
        self.cookies_label = ttk.Label(self.root, text="Cookies (name=value):")
        self.cookies_label.grid(row=6, column=0, padx=5, pady=5, sticky="w")
        self.cookies_entry = ttk.Entry(self.root, width=50)
        self.cookies_entry.grid(row=6, column=1, columnspan=2, padx=5, pady=5, sticky="we")

        # Send Request Button
        self.send_button = ttk.Button(self.root, text="Send Request", command=self.send_request)
        self.send_button.grid(row=7, column=1, padx=5, pady=5, sticky="e")

        # Response Display
        self.response_label = ttk.Label(self.root, text="Response:")
        self.response_label.grid(row=8, column=0, padx=5, pady=5, sticky="w")
        self.response_text = tk.Text(self.root, height=10, width=50)
        self.response_text.grid(row=8, column=1, columnspan=2, padx=5, pady=5, sticky="we")

        # Response Cookies Display
        self.response_cookies_label = ttk.Label(self.root, text="Response Cookies:")
        self.response_cookies_label.grid(row=9, column=0, padx=5, pady=5, sticky="w")
        self.response_cookies_text = tk.Text(self.root, height=5, width=50)
        self.response_cookies_text.grid(row=9, column=1, columnspan=2, padx=5, pady=5, sticky="we")

    def verify_credentials(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username == "admin" and password == "admin":  # Example: simple hard-coded check
            self.setup_request_ui()
        else:
            messagebox.showerror("Login failed", "The username or password is incorrect")

    def parse_cookies(self):
        cookies_str = self.cookies_entry.get()
        cookies = {}
        if cookies_str:
            for cookie in cookies_str.split(';'):
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
        return cookies

    def send_request(self):
        url = self.url_entry.get().strip('/')
        method = self.method_combobox.get()
        cookies = self.parse_cookies()

        # Set a timeout value of 5 seconds for the request
        timeout_value = 5

        try:
            session = requests.Session()
            response = session.request(method, url, cookies=cookies, timeout=timeout_value)
            self.response_text.delete('1.0', tk.END)
            self.response_text.insert(tk.END, f"Status Code: {response.status_code}\n{response.text}")

            # Display response cookies
            self.response_cookies_text.delete('1.0', tk.END)
            response_cookies = session.cookies.get_dict()
            self.response_cookies_text.insert(tk.END, "\n".join(f"{key}: {value}" for key, value in response_cookies.items()))
        except requests.exceptions.ReadTimeout:
            self.response_text.delete('1.0', tk.END)
            self.response_text.insert(tk.END, "Error: Server is busy or unresponsive. Please try again later.")
        except Exception as e:
            self.response_text.delete('1.0', tk.END)
            self.response_text.insert(tk.END, f"Error: {e}")

def main():
    root = tk.Tk()
    app = RequestApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
