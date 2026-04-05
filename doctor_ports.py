"""Quick runtime diagnostics for IDS startup issues."""

import os
import socket
import subprocess
import sys

import network_sensor
import host_sensor


def check_port(port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def run_lsof():
    try:
        out = subprocess.check_output(["lsof", "-nP", "-i", ":9001", "-i", ":9002"], text=True)
        return out.strip() or "(no listeners found)"
    except subprocess.CalledProcessError:
        return "(no listeners found)"
    except FileNotFoundError:
        return "lsof not installed"


def main():
    print("=== IDS Port Doctor ===")
    print(f"Python: {sys.executable}")
    print(f"CWD: {os.getcwd()}")
    print(f"network_sensor module: {network_sensor.__file__}")
    print(f"host_sensor module:    {host_sensor.__file__}")

    p9001_free = check_port(9001)
    p9002_free = check_port(9002)
    print(f"Port 9001 free: {p9001_free}")
    print(f"Port 9002 free: {p9002_free}")

    print("\nActive listeners (lsof):")
    print(run_lsof())

    if p9001_free and p9002_free:
        print("\nStatus: ports are free. If you still see old traceback lines, you are running a different code copy.")
    else:
        print("\nStatus: at least one IDS port is busy. Kill shown PIDs, then restart main.py.")


if __name__ == "__main__":
    main()
