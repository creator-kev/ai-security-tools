"""
Pytest configuration for AI Security Tools
"""

import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Test configuration
pytest_plugins = []

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (requires model downloads)"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "requires_api: marks tests that require API keys"
    )
