"""Tests for vulnerability scanner"""

import pytest
import aiohttp
from vulnscan import VulnerabilityScanner
from unittest.mock import Mock, patch

@pytest.fixture
async def scanner():
    scanner = VulnerabilityScanner("https://example.com")
    await scanner.initialize()
    yield scanner
    await scanner.cleanup()

@pytest.mark.asyncio
async def test_scanner_initialization(scanner):
    assert scanner._initialized
    assert scanner.session_manager is not None

@pytest.mark.asyncio
async def test_url_validation():
    with pytest.raises(ValueError):
        VulnerabilityScanner("invalid-url")

@pytest.mark.asyncio
async def test_rate_limiting(scanner):
    start_time = time.time()
    for _ in range(5):
        await scanner.rate_limiter.acquire()
    duration = time.time() - start_time
    assert duration >= 0.4  # Assuming 10 requests per second 