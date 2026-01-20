from typing import Generator
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def mock_getpass() -> Generator[None, None, None]:
    with patch("getpass.getpass", return_value="CorrectHorseBatteryStaple123!"):
        yield


@pytest.fixture
def mock_prompts() -> Generator[None, None, None]:
    with patch("click.prompt", return_value="testpass"):
        yield
