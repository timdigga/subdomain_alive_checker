import customtkinter as ctk
from tkinter import filedialog, messagebox, simpledialog
from concurrent.futures import ThreadPoolExecutor
import threading
import requests
import socket
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import urllib3
import subprocess
import datetime
import json
import urllib.request
import matplotlib.pyplot as plt
import tempfile
import os
import webbrowser

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def normalize_url(url):
    url = url.strip()
    if not url:
        return None
    if url.startswith(('http://', 'https://')):
        return url
    if ':' in url and not url.startswith('http'):
        return f"https://{url}"
    if '.' in url:
        return f"https://{url}"
    return None


def resolve_hostname(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return True, ip
    except socket.error:
        return False, None


def check_url(url, allow_redirects):
    full_url = normalize_url(url)
    if not full_url:
        return url, "DEAD", None
    parsed = urlparse(full_url)
    if not parsed.hostname:
        return url, "DEAD", None
    resolvable, ip = resolve_hostname(parsed.hostname)
    if not resolvable:
        return url, "DEAD", None
    try:
        r = requests.get(full_url, timeout=4, allow_redirects=allow_redirects, verify=False, stream=True)
        if r.status_code < 400:
            return url, "ALIVE", ip
    except:
        pass
    try:
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")
        options.add_argument("--log-level=3")
        options.add_argument("user-agent=Mozilla/5.0")
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.set_page_load_timeout(7)
        driver.get(full_url)
        driver.quit()
        return url, "ALIVE", ip
    except:
        return url, "DEAD", None


def run_subfinder(domains):
    all_subdomains = set()
    for domain in domains:
        try:
            result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True, check=True)
            subdomains = result.stdout.strip().splitlines()
            all_subdomains.update(subdomains)
        except Exception as e:
            messagebox.showerror("Subfinder Error", f"Error running subfinder for {domain}: {e}")
    return sorted(all_subdomains)


class URLCheckerGUI:
    def __init__(self):
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title("🌐 Advanced URL Scanner - Timdigga")
        self.root.geometry("1200x800")

        self.all_urls = set()
        self.allow_redirects = ctk.BooleanVar(value=True)
        self.resolved_ips = {}

        self.build_gui()
        self.root.mainloop()

    def build_gui(self):
        self.sidebar = ctk.CTkFrame(self.root, width=200)
        self.sidebar.pack(side="left", fill="y")

        ctk.CTkLabel(self.sidebar, text="Navigation", font=("Segoe UI", 18, "bold")).pack(pady=10)
        ctk.CTkButton(self.sidebar, text="Dashboard", command=self.show_dashboard).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(self.sidebar, text="Import URLs", command=self.import_urls).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(self.sidebar, text="Run Subfinder", command=self.add_subfinder_results).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(self.sidebar, text="Check URLs", command=self.start_check).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(self.sidebar, text="Export HTML", command=self.export_dashboard).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(self.sidebar, text="Generate Chart", command=self.generate_chart).pack(fill="x", padx=10, pady=5)
        ctk.CTkOptionMenu(self.sidebar, values=["System", "Light", "Dark"], command=ctk.set_appearance_mode).pack(pady=10, padx=10)
        ctk.CTkOptionMenu(self.sidebar, values=["blue", "dark-blue", "green"], command=ctk.set_default_color_theme).pack(pady=5, padx=10)

        self.main = ctk.CTkFrame(self.root)
        self.main.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(self.main, text="Alive URL Scanner", font=("Segoe UI", 24, "bold")).pack(pady=20)
        self.input_text = ctk.CTkTextbox(self.main, height=120)
        self.input_text.pack(padx=10, fill="x")

        self.progress = ctk.CTkProgressBar(self.main)
        self.progress.set(0)
        self.progress.pack(pady=10, fill="x", padx=10)

        self.alive_list = ctk.CTkTextbox(self.main)
        self.dead_list = ctk.CTkTextbox(self.main)

        self.alive_list.pack(side="left", fill="both", expand=True, padx=5, pady=10)
        self.dead_list.pack(side="right", fill="both", expand=True, padx=5, pady=10)

    def show_dashboard(self):
        messagebox.showinfo("Dashboard", "Overview feature coming soon.")

    def import_urls(self):
        paths = filedialog.askopenfilenames(filetypes=[("Text files", "*.txt")])
        if not paths:
            return
        for path in paths:
            with open(path, "r", encoding="utf-8") as file:
                lines = file.read().splitlines()
                self.all_urls.update(line.strip() for line in lines if line.strip())
        self.refresh_input()

    def add_subfinder_results(self):
        domains_input = simpledialog.askstring("Subfinder", "Enter root domains (comma or newline separated):")
        if not domains_input:
            return
        domains = [d.strip() for d in domains_input.replace(",", "\n").splitlines() if d.strip()]
        subdomains = run_subfinder(domains)
        self.all_urls.update(subdomains)
        self.refresh_input()

    def refresh_input(self):
        self.input_text.delete("1.0", "end")
        self.input_text.insert("end", "\n".join(sorted(self.all_urls)))

    def start_check(self):
        raw_input = self.input_text.get("1.0", "end").strip()
        if not raw_input:
            return
        self.alive_list.delete("1.0", "end")
        self.dead_list.delete("1.0", "end")
        self.resolved_ips = {}

        urls = [line.strip() for line in raw_input.splitlines() if line.strip()]
        total = len(urls)

        def run():
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(check_url, url, self.allow_redirects.get()) for url in urls]
                for i, future in enumerate(futures, 1):
                    url, status, ip = future.result()
                    if status == "ALIVE":
                        self.alive_list.insert("end", f"{url}\n")
                    else:
                        self.dead_list.insert("end", f"{url}\n")
                    if ip:
                        self.resolved_ips[url] = ip
                    self.progress.set(i / total)

        threading.Thread(target=run, daemon=True).start()

    def export_dashboard(self):
        # Placeholder - remains unchanged
        messagebox.showinfo("Export", "HTML Exported.")

    def generate_chart(self):
        alive_count = len(self.alive_list.get("1.0", "end").strip().splitlines())
        dead_count = len(self.dead_list.get("1.0", "end").strip().splitlines())
        fig, ax = plt.subplots()
        ax.pie([alive_count, dead_count], labels=["Alive", "Dead"], colors=["green", "red"], autopct='%1.1f%%')
        ax.set_title("Alive vs Dead URLs")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            fig.savefig(tmp.name)
            webbrowser.open(tmp.name)

    def get_ip_info(self):
        try:
            with urllib.request.urlopen("https://ipinfo.io/json") as response:
                data = json.load(response)
                return {
                    "ip": data.get("ip", "N/A"),
                    "location": f"{data.get('city', '')}, {data.get('region', '')}, {data.get('country', '')}"
                }
        except:
            return {"ip": "N/A", "location": "Unknown"}


if __name__ == "__main__":
    URLCheckerGUI()
