import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
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
import os
import json
import urllib.request

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

def is_resolvable(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False

def check_url(url, allow_redirects):
    full_url = normalize_url(url)
    if not full_url:
        return url, "DEAD"
    parsed = urlparse(full_url)
    if not parsed.hostname or not is_resolvable(parsed.hostname):
        return url, "DEAD"
    try:
        r = requests.get(full_url, timeout=4, allow_redirects=allow_redirects, verify=False, stream=True)
        if r.status_code < 400:
            return url, "ALIVE"
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
        return url, "ALIVE"
    except:
        return url, "DEAD"

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
    def get_current_ip_info(self):
        try:
            with urllib.request.urlopen("https://ipinfo.io/json") as response:
                data = json.load(response)
                return {
                    "ip": data.get("ip", "N/A"),
                    "location": f"{data.get('city', '')}, {data.get('region', '')}, {data.get('country', '')}",
                    "org": data.get("org", "Unknown"),
                    "coordinates": data.get("loc", "Unknown")
                }
        except:
            return {
                "ip": "N/A",
                "location": "Unknown",
                "org": "Unknown",
                "coordinates": "Unknown"
            }
    def __init__(self, root):
        self.root = root
        self.root.title("🌐 Alive URL Scanner - Timdigga")
        self.root.geometry("1000x750")
        self.root.configure(bg="#121212")
        self.all_urls = set()
        self.allow_redirects = tk.BooleanVar(value=True)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", padding=6, font=("Segoe UI", 12))
        style.configure("TCheckbutton", background="#121212", foreground="white")
        style.configure("TProgressbar", troughcolor="#333", background="#00ff99", thickness=20)
        self.setup_widgets()

    def setup_widgets(self):
        tk.Label(self.root, text="Alive URL Scanner", font=("Segoe UI", 24, "bold"), bg="#121212", fg="white").pack(pady=20)
        self.input_text = scrolledtext.ScrolledText(self.root, height=8, font=("Consolas", 12), bg="#1e1e1e", fg="white", insertbackground="white")
        self.input_text.pack(fill=tk.X, padx=20, pady=10)
        btn_frame = tk.Frame(self.root, bg="#121212")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="📂 Import URLs", command=self.import_urls).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="🌐 Subfinder", command=self.add_subfinder_results).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="🚀 Check URLs", command=self.start_check).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="📊 Export Dashboard", command=self.export_dashboard).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(self.root, text="Allow Redirects", variable=self.allow_redirects).pack(pady=5)
        self.progress_var = tk.IntVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=20, pady=10)
        result_frame = tk.Frame(self.root, bg="#121212")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        self.alive_list = tk.Listbox(result_frame, fg="#00ff99", bg="#1e1e1e", font=("Consolas", 12))
        self.dead_list = tk.Listbox(result_frame, fg="#ff5555", bg="#1e1e1e", font=("Consolas", 12))
        self.alive_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.dead_list.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

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
        domains_input = tk.simpledialog.askstring("Subfinder", "Enter root domains (comma or newline separated):")
        if not domains_input:
            return
        domains = [d.strip() for d in domains_input.replace(",", "\n").splitlines() if d.strip()]
        subdomains = run_subfinder(domains)
        self.all_urls.update(subdomains)
        self.refresh_input()

    def refresh_input(self):
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert(tk.END, "\n".join(sorted(self.all_urls)))

    def start_check(self):
        raw_input = self.input_text.get("1.0", tk.END).strip()
        if not raw_input:
            return
        self.alive_list.delete(0, tk.END)
        self.dead_list.delete(0, tk.END)
        urls = [line.strip() for line in raw_input.splitlines() if line.strip()]
        total = len(urls)
        self.progress_var.set(0)
        self.progress_bar.config(maximum=total)
        def run_checks():
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(check_url, url, self.allow_redirects.get()) for url in urls]
                for i, future in enumerate(futures, 1):
                    url, status = future.result()
                    if status == "ALIVE":
                        self.alive_list.insert(tk.END, url)
                    else:
                        self.dead_list.insert(tk.END, url)
                    self.progress_var.set(i)
        threading.Thread(target=run_checks, daemon=True).start()

    def export_dashboard(self):
        ip_info = self.get_current_ip_info()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alive = self.alive_list.get(0, tk.END)
        dead = self.dead_list.get(0, tk.END)
        alive_html = ''.join(f"<tr><td>{url}</td><td>N/A</td><td>{timestamp}</td></tr>" for url in alive)
        dead_html = ''.join(f"<li class='dead-url'>{url}</li>" for url in dead)
        html = f"""
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<title>Timdigga URL Dashboard</title>
<style>
body {{ background-color: #101010; color: #eee; font-family: 'Segoe UI', sans-serif; margin: 0; }}
header {{ background: #000; padding: 20px; text-align: center; border-bottom: 2px solid #00ff99; }}
header h1 {{ color: #00ff99; margin: 0; }}
section {{ padding: 20px; }}
h2 {{ color: #00ff99; border-bottom: 1px solid #00ff99; padding-bottom: 5px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th, td {{ padding: 10px; border: 1px solid #333; }}
th {{ background: #222; color: #00ff99; }}
tr:nth-child(even) {{ background: #181818; }}
.dead-url {{ color: #ff5555; }}
footer {{ text-align: center; padding: 10px; font-size: 0.9em; background: #000; margin-top: 40px; color: #999; }}
.info-block {{ margin: 20px 0; padding: 10px; background: #1a1a1a; border-left: 4px solid #00ff99; }}
</style>
</head>
<body>
<header>
    <h1>Timdigga - URL Scan Dashboard</h1>
</header>
<section>
    <div class='info-block'>
        <h2>You're informations! If they are real, make sure you use a VPN!</h2>
        <p><strong>IP Address:</strong> {ip_info['ip']}</p>
        <p><strong>Location:</strong> {ip_info['location']}</p>
        <p><strong>ISP/Org:</strong> {ip_info['org']}</p>
        <p><strong>Coordinates:</strong> {ip_info['coordinates']}</p>
        <p><strong>Scan Timestamp:</strong> {timestamp}</p>
    </div>
    <h2>✅ Alive URLs</h2>
    <table>
        <tr><th>URL</th><th>Resolved IP</th><th>Checked At</th></tr>
        {alive_html}
    </table>
    <h2>❌ Dead URLs</h2>
    <ul>
        {dead_html}
    </ul>
</section>
<footer>
    Report generated by <a href="https://github.com/timdigga" target="_blank" style="color:#00ff99;">timdigga</a>
</footer>
</body>
</html>
"""
        filepath = filedialog.asksaveasfilename(defaultextension=".html")
        if filepath:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)
            messagebox.showinfo("Export", f"Saved to {filepath}")

if __name__ == "__main__":
    root = tk.Tk()
    app = URLCheckerGUI(root)
    root.mainloop()
