# -*- coding: utf-8 -*-
"""Location: ./tests/conftest.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti
"""

# Standard
import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, patch

# Third-Party
from _pytest.monkeypatch import MonkeyPatch
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# First-Party
from mcpgateway.config import Settings
from mcpgateway.db import Base


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_db_url():
    """Return the URL for the test database."""
    return "sqlite:///:memory:"


@pytest.fixture(scope="session")
def test_engine(test_db_url):
    """Create a SQLAlchemy engine for testing."""
    engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    if os.path.exists("./test.db"):
        os.remove("./test.db")


@pytest.fixture
def test_db(test_engine):
    """Create a fresh database session for a test."""
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def test_settings():
    """Create test settings with in-memory database."""
    return Settings(
        database_url="sqlite:///:memory:",
        basic_auth_user="testuser",
        basic_auth_password="testpass",
        auth_required=False,
        mcp_client_auth_enabled=False,
    )


@pytest.fixture
def app():
    """Create a FastAPI test application with proper database setup."""
    # Use the existing app_with_temp_db fixture logic which works correctly
    mp = MonkeyPatch()

    # 1) create temp SQLite file
    fd, path = tempfile.mkstemp(suffix=".db")
    url = f"sqlite:///{path}"

    # 2) patch settings
    from mcpgateway.config import settings
    mp.setattr(settings, "database_url", url, raising=False)

    # First-Party
    import mcpgateway.db as db_mod

    engine = create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    mp.setattr(db_mod, "engine", engine, raising=False)
    mp.setattr(db_mod, "SessionLocal", TestSessionLocal, raising=False)

    # 4) patch the already‑imported main module **without reloading**
    import mcpgateway.main as main_mod
    mp.setattr(main_mod, "SessionLocal", TestSessionLocal, raising=False)
    # (patch engine too if your code references it)
    mp.setattr(main_mod, "engine", engine, raising=False)

    # 4) create schema
    db_mod.Base.metadata.create_all(bind=engine)

    # First-Party
    from mcpgateway.main import app

    yield app

    # 6) teardown
    mp.undo()
    engine.dispose()
    os.close(fd)
    os.unlink(path)


@pytest.fixture
def mock_http_client():
    """Create a mock HTTP client."""
    mock = AsyncMock()
    mock.aclose = AsyncMock()
    return mock


@pytest.fixture
def mock_websocket():
    """Create a mock WebSocket."""
    mock = AsyncMock()
    mock.accept = AsyncMock()
    mock.send_json = AsyncMock()
    mock.receive_json = AsyncMock()
    mock.close = AsyncMock()
    return mock


# @pytest.fixture(scope="session", autouse=True)
# def _patch_stdio_first():
#     """
#     Runs once, *before* the test session collects other modules,
#     so no rogue coroutine can be created.
#     """
#     import mcpgateway.translate as translate
#     translate._run_stdio_to_sse = AsyncMock(return_value=None)
#     translate._run_sse_to_stdio = AsyncMock(return_value=None)


@pytest.fixture(scope="module")  # one DB per test module is usually fine
def app_with_temp_db():
    """Return a FastAPI app wired to a fresh SQLite database."""
    mp = MonkeyPatch()

    # 1) create temp SQLite file
    fd, path = tempfile.mkstemp(suffix=".db")
    url = f"sqlite:///{path}"

    # 2) patch settings
    # First-Party
    from mcpgateway.config import settings

    mp.setattr(settings, "database_url", url, raising=False)

    # First-Party
    import mcpgateway.db as db_mod

    engine = create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    mp.setattr(db_mod, "engine", engine, raising=False)
    mp.setattr(db_mod, "SessionLocal", TestSessionLocal, raising=False)

    # 4) patch the already‑imported main module **without reloading**
    # First-Party
    import mcpgateway.main as main_mod

    mp.setattr(main_mod, "SessionLocal", TestSessionLocal, raising=False)
    # (patch engine too if your code references it)
    mp.setattr(main_mod, "engine", engine, raising=False)

    # 4) create schema
    db_mod.Base.metadata.create_all(bind=engine)

    # 5) reload main so routers, deps pick up new SessionLocal
    # if "mcpgateway.main" in sys.modules:
    #     import importlib

    #     importlib.reload(sys.modules["mcpgateway.main"])
    # else:
    #     import mcpgateway.main  # noqa: F401

    # First-Party
    from mcpgateway.main import app

    yield app

    # 6) teardown
    mp.undo()
    engine.dispose()
    os.close(fd)
    os.unlink(path)
