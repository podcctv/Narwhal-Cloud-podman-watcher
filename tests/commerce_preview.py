"""Loopback-only synthetic business UI fixture. Never connects to upstream."""
import tempfile
from pathlib import Path

import uvicorn
from server import app as server, commerce
from tests.test_commerce import fixture, uid


def demo():
    data = fixture()
    data["machines"].append({**data["machines"][0], "id": uid(200), "name": "合成测试母鸡 B", "sold_current": 1, "self_current": 2, "buyer_count": 1, "observed_vms": 3, "vm_count": 3, "earned_revenue": "3.5"})
    data["orders"].append({**data["orders"][0], "id": uid(201), "machine_id": uid(200), "machine_name": "合成测试母鸡 B", "created_at": 1704412800, "amount": "1.25"})
    for i in range(55):
        data["orders"].append({**data["orders"][0], "id": uid(300+i), "created_at": 1704412800 + i*86400, "amount": "0.01"})
    return data


def main():
    with tempfile.TemporaryDirectory(prefix="narwhal-commerce-preview-") as temp:
        server.DB_PATH = str(Path(temp) / "preview.db")
        server.DASHBOARD_USERNAME = "preview"
        server.DASHBOARD_PASSWORD = "local-preview-only"
        server.APP_VERSION = "test-data"
        commerce.profile = lambda client: fixture()["profile"]
        commerce.snapshot = lambda client, account: demo()
        uvicorn.run(server.app, host="127.0.0.1", port=8787, log_level="warning")


if __name__ == "__main__":
    main()
