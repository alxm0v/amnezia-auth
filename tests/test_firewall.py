import pytest
from unittest.mock import patch, MagicMock
import subprocess
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Set required environment variables for pydantic_settings before importing anything that loads config
os.environ["SECRET_KEY"] = "dummy_secret_key_for_testing"

from firewall import grant_access, revoke_access, check_access

# Note: In a real project, we would need to mock the logger as well or let it print to stdout.
# Assuming firewall.py is in the parent directory, we might need to adjust PYTHONPATH.
# Since we are running pytest from the amnezia-auth root, imports should work if we create an __init__.py
# or just import directly if firewall.py is in the root.

@patch("subprocess.run")
def test_grant_access_new_rule(mock_run):
    # Setup mock for check_access (returns 1, meaning rule doesn't exist)
    mock_check_result = MagicMock()
    mock_check_result.returncode = 1
    
    # Setup mock for adding rule
    mock_add_result = MagicMock()
    mock_add_result.returncode = 0
    
    # Configure mock_run to return check_result first, then add_result
    mock_run.side_effect = [mock_check_result, mock_add_result]
    
    grant_access("10.0.42.5")
    
    assert mock_run.call_count == 2
    # Verify check call
    mock_run.assert_any_call(["iptables", "-C", "AMNEZIA_AUTH", "-s", "10.0.42.5", "-j", "VPN_RULES"], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Verify add call
    mock_run.assert_any_call(["iptables", "-A", "AMNEZIA_AUTH", "-s", "10.0.42.5", "-j", "VPN_RULES"], check=True)

@patch("subprocess.run")
def test_grant_access_existing_rule(mock_run):
    # Rule already exists
    mock_check_result = MagicMock()
    mock_check_result.returncode = 0
    mock_run.return_value = mock_check_result
    
    grant_access("10.0.42.5")
    
    assert mock_run.call_count == 1
    mock_run.assert_called_once_with(["iptables", "-C", "AMNEZIA_AUTH", "-s", "10.0.42.5", "-j", "VPN_RULES"], 
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

@patch("subprocess.run")
def test_revoke_access(mock_run):
    # Setup mock: first call returns 0 (deleted), second returns 1 (no more rules)
    mock_success = MagicMock()
    mock_success.returncode = 0
    mock_fail = MagicMock()
    mock_fail.returncode = 1
    
    mock_run.side_effect = [mock_success, mock_fail]
    
    revoke_access("10.0.42.5")
    
    assert mock_run.call_count == 2
    mock_run.assert_called_with(["iptables", "-D", "AMNEZIA_AUTH", "-s", "10.0.42.5", "-j", "VPN_RULES"], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

@patch("subprocess.run")
def test_check_access_true(mock_run):
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result
    
    assert check_access("10.0.42.5") is True

@patch("subprocess.run")
def test_check_access_false(mock_run):
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_run.return_value = mock_result
    
    assert check_access("10.0.42.5") is False
