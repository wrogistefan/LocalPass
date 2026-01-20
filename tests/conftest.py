import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_prompts():
    with patch('click.prompt', return_value="testpass"), \
         patch('getpass.getpass', return_value="testpass"):
        yield