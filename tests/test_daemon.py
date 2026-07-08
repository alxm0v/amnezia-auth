import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
os.environ["SECRET_KEY"] = "dummy_secret_key_for_testing"

from daemon import app, DAEMON_API_KEY
from config import settings

client = TestClient(app)

valid_headers = {"Authorization": f"Bearer {DAEMON_API_KEY}"}

@patch("daemon.daemon_check_access", return_value=False)
@patch("daemon.daemon_grant_access")
def test_grant_authorized(mock_grant, mock_check):
    response = client.post("/grant?ip=10.0.42.5", headers=valid_headers)
    assert response.status_code == 200
    mock_grant.assert_called_once_with("10.0.42.5")

def test_grant_unauthorized_no_header():
    response = client.post("/grant?ip=10.0.42.5")
    assert response.status_code == 401

def test_grant_unauthorized_wrong_header():
    response = client.post("/grant?ip=10.0.42.5", headers={"Authorization": "Bearer wrong_key"})
    assert response.status_code == 401

def test_grant_invalid_ip():
    response = client.post("/grant?ip=not_an_ip", headers=valid_headers)
    assert response.status_code == 422 # Pydantic validation error

@patch("daemon.daemon_check_access", return_value=True)
@patch("daemon.daemon_revoke_access")
def test_revoke_authorized(mock_revoke, mock_check):
    response = client.post("/revoke?ip=10.0.42.5", headers=valid_headers)
    assert response.status_code == 200
    mock_revoke.assert_called_once_with("10.0.42.5")

@patch("daemon.daemon_check_access", return_value=True)
def test_check_authorized(mock_check):
    response = client.get("/check?ip=10.0.42.5", headers=valid_headers)
    assert response.status_code == 200
    assert response.json() == {"access": True}
