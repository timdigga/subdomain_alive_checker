# Timdigga Subdomain Finder (ALIVE + DEAD CHECK)

## Description

A GUI tool that checks if URLs are alive or dead using:

- Quick HEAD request with `requests`
- Full page load test using `Selenium` (with aggressive timeout to prevent hanging)
- Multithreading for faster scans
- Subfinder integration to collect subdomains automatically

## Installation

### Install Python 3.x

https://www.python.org/downloads/

### Clone repository

```bash
git clone https://github.com/timdigga/subdomain_alive_checker.git
cd YOUR_REPO_NAME
```
# Install requirements
```bash
pip install -r requirements.txt
```
Install subfinder
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Paste or import URLs into the app.
Click Check URLs to start.
Results will be shown and copyable.
