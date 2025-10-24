import os
import sys
import subprocess
import requests
import importlib.util

UPDATE_URL = "https://raw.githubusercontent.com/SourcePhobia/sealchat/main/client.py"
REQUIREMENTS_URL = "https://raw.githubusercontent.com/SourcePhobia/sealchat/refs/heads/autoupdate/requirements.txt"

def is_package_installed(pkg_name):
    return importlib.util.find_spec(pkg_name) is not None

def install_packages(packages):
    for pkg in packages:
        if is_package_installed(pkg):
            print(f"[Bootstrapper] Package '{pkg}' is already installed.")
        else:
            print(f"[Bootstrapper] Installing '{pkg}'...")
            subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", pkg], check=True)

def fetch_requirements(url):
    try:
        r = requests.get(url)
        r.raise_for_status()
        return [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"[Bootstrapper] Failed to fetch requirements: {e}")
        return []

def fetch_client_code(url):
    try:
        r = requests.get(url)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[Bootstrapper] Failed to fetch client code: {e}")
        sys.exit(1)

def main():
    print("[Bootstrapper] Starting bootstrapper...")

    print("[Bootstrapper] Fetching required packages from remote...")
    required_packages = fetch_requirements(REQUIREMENTS_URL)
    if required_packages:
        print(f"[Bootstrapper] Installing/updating packages: {', '.join(required_packages)}")
        install_packages(required_packages)
    else:
        print("[Bootstrapper] No packages found to install.")

    client_code = fetch_client_code(UPDATE_URL)

    os.system("cls" if os.name == "nt" else "clear")

    print("[Bootstrapper] Launching client...")
    exec(client_code, {"__name__": "__main__"})

if __name__ == "__main__":
    main()

