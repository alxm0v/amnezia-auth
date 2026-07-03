import pytest
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
os.environ["SECRET_KEY"] = "dummy_secret_key_for_testing"

from firewall import grant_access, revoke_access, check_access

DAEMON_URL = "http://127.0.0.1:9000"

@patch("firewall.httpx.post")
def test_grant_access(mock_post):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response
    
    grant_access("10.0.42.5")
    
    mock_post.assert_called_once_with(f"{DAEMON_URL}/grant", params={"ip": "10.0.42.5"}, timeout=5.0)
    mock_response.raise_for_status.assert_called_once()


@patch("firewall.httpx.post")
def test_revoke_access(mock_post):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response
    
    revoke_access("10.0.42.5")
    
    mock_post.assert_called_once_with(f"{DAEMON_URL}/revoke", params={"ip": "10.0.42.5"}, timeout=5.0)
    mock_response.raise_for_status.assert_called_once()


@patch("firewall.httpx.get")
def test_check_access_true(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"access": True}
    mock_get.return_value = mock_response
    
    assert check_access("10.0.42.5") is True
    mock_get.assert_called_once_with(f"{DAEMON_URL}/check", params={"ip": "10.0.42.5"}, timeout=5.0)


@patch("firewall.httpx.get")
def test_check_access_false(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"access": False}
    mock_get.return_value = mock_response
    
    assert check_access("10.0.42.5") is False
    mock_get.assert_called_once_with(f"{DAEMON_URL}/check", params={"ip": "10.0.42.5"}, timeout=5.0)


@patch("firewall.httpx.get")
def test_check_access_error(mock_get):
    # Simulate daemon being down
    mock_get.side_effect = Exception("Connection refused")
    
    assert check_access("10.0.42.5") is False
    mock_get.assert_called_once_with(f"{DAEMON_URL}/check", params={"ip": "10.0.42.5"}, timeout=5.0)
