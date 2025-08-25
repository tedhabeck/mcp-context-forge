# -*- coding: utf-8 -*-
"""Migration testing package for MCP Gateway.

This package provides comprehensive database migration testing capabilities
across multiple container versions and database backends (SQLite, PostgreSQL).

Key components:
- Container management for Docker/Podman orchestration
- Migration test runners with detailed logging
- Schema validation and comparison utilities
- Performance benchmarking and reporting
- Test fixtures for various migration scenarios

Usage:
    pytest tests/migration/ -v --tb=short
    make test-migration-all
"""
