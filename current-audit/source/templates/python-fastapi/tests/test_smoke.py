from fastapi.testclient import TestClient
from app.main import app
def test_health() -> None:
    assert TestClient(app).get("/healthz").json()=={"ok":True}
