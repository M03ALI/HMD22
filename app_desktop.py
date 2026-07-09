"""
Health Data Matrics — Hospital KPI Dashboard (desktop launcher)

Runs the dashboard as a standalone Windows app. Streamlit is used only as the
internal engine: it is started silently on a local port and shown in a native
window (no browser chrome, no Deploy button). If the native window cannot start
on a given machine, it falls back to opening the default browser so the app
still works. The database is kept in a persistent per-user folder.
"""

import os
import sys
import time
import socket
import shutil
import subprocess

APP_NAME = "Health Data Matrics — Hospital KPI Dashboard"


def resource_path(rel):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


def user_data_dir():
    root = (os.environ.get("APPDATA") if os.name == "nt" else None) \
        or os.path.join(os.path.expanduser("~"), ".local", "share")
    d = os.path.join(root, "HealthDataMatrics")
    os.makedirs(os.path.join(d, ".streamlit"), exist_ok=True)
    return d


def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_server(port, timeout=120):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def run_streamlit(port):
    """Child process: start the Streamlit server for the bundled app."""
    data_dir = user_data_dir()
    os.environ["HOSPITAL_DB_PATH"] = os.path.join(data_dir, "hospital_dashboard.db")
    os.environ["HDM_DESKTOP"] = "1"  # tells the app to save downloads to disk
    try:
        shutil.copyfile(resource_path(os.path.join(".streamlit", "config.toml")),
                        os.path.join(data_dir, ".streamlit", "config.toml"))
    except Exception:
        pass
    os.chdir(data_dir)

    os.environ.setdefault("STREAMLIT_SERVER_HEADLESS", "true")
    os.environ.setdefault("STREAMLIT_BROWSER_GATHER_USAGE_STATS", "false")
    os.environ.setdefault("STREAMLIT_GLOBAL_DEVELOPMENT_MODE", "false")

    from streamlit.web import cli as stcli
    sys.argv = [
        "streamlit", "run", resource_path("hospitalapp.py"),
        "--server.port", str(port),
        "--server.address", "127.0.0.1",
        "--server.headless", "true",
        "--browser.gatherUsageStats", "false",
        "--global.developmentMode", "false",
        "--server.fileWatcherType", "none",
        "--client.toolbarMode", "minimal",
    ]
    sys.exit(stcli.main())


def open_window(url):
    """Native window if possible; otherwise the default browser."""
    try:
        import webview
        webview.create_window(APP_NAME, url, width=1400, height=900,
                              min_size=(1024, 720))
        webview.start()
    except Exception:
        import webbrowser
        webbrowser.open(url)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass


def main():
    if "--serve" in sys.argv:
        run_streamlit(int(os.environ["HDM_PORT"]))
        return

    port = find_free_port()
    env = dict(os.environ, HDM_PORT=str(port))
    cmd = [sys.executable, "--serve"] if getattr(sys, "frozen", False) \
        else [sys.executable, os.path.abspath(__file__), "--serve"]
    flags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
    proc = subprocess.Popen(cmd, env=env, creationflags=flags)
    try:
        if not wait_for_server(port):
            raise RuntimeError("The dashboard engine did not start in time.")
        open_window(f"http://127.0.0.1:{port}")
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


if __name__ == "__main__":
    main()
