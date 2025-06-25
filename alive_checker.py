import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
from concurrent.futures import ThreadPoolExecutor
import threading
import subprocess
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException
from webdriver_manager.chrome import ChromeDriverManager
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Disclaimer ===
def show_disclaimer():
    disclaimer_text = (
        "Disclaimer:\n\n"
        "This tool is for educational and internal testing purposes only.\n"
        "Do not use it to scan or probe systems without proper authorization.\n"
        "Use of this tool is your responsibility. Timdigga is not liable for any misuse."
    )
    messagebox.showinfo("Disclaimer", disclaimer_text)

# === Subfinder Integration ===
def run_subfinder():
    domains_input = simpledialog.askstring("Subfinder", "Enter root domains (comma or newline separated):")
    if not domains_input:
        return

    domains = [d.strip() for d in domains_input.replace(",", "\n").splitlines() if d.strip()]
    all_subdomains = set()

    for domain in domains:
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True, text=True, check=True
            )
            subdomains = result.stdout.strip().splitlines()
            all_subdomains.update(subdomains)
        except FileNotFoundError:
            messagebox.showerror("Error", "Subfinder not found. Please ensure it's installed and in PATH.")
            return
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Subfinder error for domain {domain}:\n{e.stderr}")
            return

    if not all_subdomains:
        messagebox.showinfo("Subfinder", "No subdomains found for any domain.")
        return

    input_text.delete("1.0", tk.END)
    input_text.insert(tk.END, "\n".join(sorted(all_subdomains)))
    messagebox.showinfo("Subfinder", f"Imported {len(all_subdomains)} subdomains from {len(domains)} domains.")

# === Improved URL Checking ===
def check_url(url):
    full_url = "https://" + url.strip()

    # STEP 1: Quick HEAD request first
    try:
        r = requests.head(full_url, timeout=2, allow_redirects=True, verify=False)
        if r.status_code >= 500:
            return url, "DEAD"
    except:
        return url, "DEAD"

    # STEP 2: Selenium full page load with aggressive timeout
    try:
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")
        options.add_argument("--log-level=3")

        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.set_page_load_timeout(3)
        driver.get(full_url)
        driver.quit()
        return url, "ALIVE"
    except TimeoutException:
        return url, "DEAD"
    except:
        return url, "DEAD"

def start_check():
    raw_input = input_text.get("1.0", tk.END).strip()
    if not raw_input:
        return

    urls = [line.strip() for line in raw_input.splitlines() if line.strip()]
    total = len(urls)
    alive_list.delete(0, tk.END)
    dead_list.delete(0, tk.END)
    progress_var.set(0)
    progress_bar.config(maximum=total)

    def run_checks():
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for url in urls:
                future = executor.submit(check_url, url)
                futures.append(future)

            for i, future in enumerate(futures, 1):
                url, status = future.result()
                if status == "ALIVE":
                    alive_list.insert(tk.END, url)
                else:
                    dead_list.insert(tk.END, url)
                progress_var.set(i)

        check_button.config(state="normal")

    check_button.config(state="disabled")
    threading.Thread(target=run_checks, daemon=True).start()

def copy_alive():
    urls = alive_list.get(0, tk.END)
    if not urls:
        messagebox.showinfo("Copy Alive", "No alive URLs to copy.")
        return
    root.clipboard_clear()
    root.clipboard_append("\n".join(urls))
    root.update()
    messagebox.showinfo("Copy Alive", "Alive URLs copied to clipboard.")

def copy_dead():
    urls = dead_list.get(0, tk.END)
    if not urls:
        messagebox.showinfo("Copy Dead", "No dead URLs to copy.")
        return
    root.clipboard_clear()
    root.clipboard_append("\n".join(urls))
    root.update()
    messagebox.showinfo("Copy Dead", "Dead URLs copied to clipboard.")

# === GUI Setup ===
root = tk.Tk()
root.withdraw()
show_disclaimer()
root.deiconify()

root.title("Subfinder with health checker by Timdigga")
root.geometry("900x800")
root.configure(bg="#1e1e1e")

style = ttk.Style()
style.theme_use("clam")
style.configure("TProgressbar", troughcolor="#3a3a3a", background="#00ff99", thickness=20)

subfinder_btn = tk.Button(root, text="🔸 Run Subfinder", command=run_subfinder, font=("Arial", 12, "bold"), bg="#ffaa00", fg="black")
subfinder_btn.pack(pady=(10, 0))

tk.Label(root, text="Paste URLs or import from Subfinder below (one per line):", font=("Arial", 12), fg="white", bg="#1e1e1e").pack(anchor="w", padx=10, pady=(10, 0))
input_text = scrolledtext.ScrolledText(root, height=8, wrap=tk.WORD, font=("Consolas", 12), bg="#2b2b2b", fg="white")
input_text.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0, 10))

check_button = tk.Button(root, text="Check URLs", command=start_check, font=("Arial", 14, "bold"), bg="#00ff99", fg="black")
check_button.pack(pady=(0, 10))

progress_var = tk.IntVar()
progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100)
progress_bar.pack(fill=tk.X, padx=10, pady=5)

frame = tk.Frame(root, bg="#1e1e1e")
frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

alive_frame = tk.Frame(frame, bg="#1e1e1e")
dead_frame = tk.Frame(frame, bg="#1e1e1e")
alive_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
dead_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

tk.Label(alive_frame, text="✅ ALIVE URLs", fg="#00ff99", bg="#1e1e1e", font=("Arial", 14, "bold")).pack()
alive_list = tk.Listbox(alive_frame, fg="#00ff99", bg="#2b2b2b", font=("Consolas", 12))
alive_list.pack(fill=tk.BOTH, expand=True)
tk.Button(alive_frame, text="Copy ALIVE", command=copy_alive, bg="#007744", fg="white", font=("Arial", 12, "bold")).pack(pady=5)

tk.Label(dead_frame, text="❌ DEAD URLs", fg="#ff4444", bg="#1e1e1e", font=("Arial", 14, "bold")).pack()
dead_list = tk.Listbox(dead_frame, fg="#ff4444", bg="#2b2b2b", font=("Consolas", 12))
dead_list.pack(fill=tk.BOTH, expand=True)
tk.Button(dead_frame, text="Copy DEAD", command=copy_dead, bg="#771111", fg="white", font=("Arial", 12, "bold")).pack(pady=5)

footer = tk.Label(root, text="© 2025 Timdigga", fg="gray", bg="#1e1e1e", font=("Arial", 10))
footer.pack(side=tk.BOTTOM, pady=5)

root.mainloop()