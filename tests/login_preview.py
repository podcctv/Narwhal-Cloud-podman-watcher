"""Loopback-only auth/UI fixture, real middleware, no injected authorization."""
import tempfile
from pathlib import Path

import uvicorn
from server import app as server


def main():
    with tempfile.TemporaryDirectory(prefix="narwhal-login-preview-") as temp:
        server.DB_PATH = str(Path(temp) / "preview.db")
        server.DASHBOARD_USERNAME = "preview"
        server.DASHBOARD_PASSWORD = "local-preview-only"
        server.APP_VERSION = "1.7.7"
        uvicorn.run(server.app, host="127.0.0.1", port=8786, log_level="warning")


if __name__ == "__main__":
    main()
