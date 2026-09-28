import os
import sys
import tempfile
from pathlib import Path

# isolate every test run in its own data directory (must happen before app import)
os.environ["SIH_DATA_DIR"] = tempfile.mkdtemp(prefix="sih-test-")
os.environ["SIH_DEMO"] = "1"
os.environ["SIH_ALLOWED_HOSTS"] = "127.0.0.1,localhost,testserver"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="session")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def seeded(client):
    r = client.post("/api/demo/seed")
    assert r.status_code == 200, r.text
    return r.json()


def _login(client, name, pin):
    ops = {o["name"]: o["id"] for o in client.get("/api/auth/operators").json()}
    r = client.post("/api/auth/login", json={"operator_id": ops[name], "pin": pin})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


@pytest.fixture(scope="session")
def officer(client, seeded):
    return _login(client, "Priya Nair", "9000")


@pytest.fixture(scope="session")
def examiner(client, seeded):
    return _login(client, "Arjun Rao", "9100")


@pytest.fixture(scope="session")
def auditor(client, seeded):
    return _login(client, "Meera Das", "9200")
