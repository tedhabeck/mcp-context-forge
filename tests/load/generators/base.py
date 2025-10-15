# -*- coding: utf-8 -*-
"""Base generator class for all data generators."""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Generator, List, Optional

from faker import Faker
from sqlalchemy.orm import Session


class BaseGenerator(ABC):
    """Base class for all data generators.

    Provides common functionality for generating test data including:
    - Batch insert optimization
    - Progress tracking
    - Faker integration
    - Configuration management
    """

    def __init__(
        self,
        db: Session,
        config: Dict[str, Any],
        faker: Faker,
        logger: logging.Logger,
        existing_data: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the generator.

        Args:
            db: SQLAlchemy database session
            config: Configuration dictionary from YAML
            faker: Faker instance for generating realistic data
            logger: Logger instance
            existing_data: Optional dict of existing data for incremental mode
        """
        self.db = db
        self.config = config
        self.faker = faker
        self.logger = logger
        self.existing_data = existing_data or {}
        self.batch_size = config.get("global", {}).get("batch_size", 1000)
        self.email_domain = config.get("global", {}).get("email_domain", "loadtest.example.com")

        # Statistics
        self.generated_count = 0
        self.inserted_count = 0

    @abstractmethod
    def generate(self) -> Generator[Any, None, None]:
        """Generate records as a generator (memory efficient).

        Yields:
            Model instances ready to be inserted
        """
        pass

    @abstractmethod
    def get_count(self) -> int:
        """Get total number of records to generate.

        Returns:
            Expected number of records
        """
        pass

    @abstractmethod
    def get_dependencies(self) -> List[str]:
        """Get list of generator names this depends on.

        Returns:
            List of generator class names (e.g., ['UserGenerator', 'TeamGenerator'])
        """
        pass

    def get_name(self) -> str:
        """Get the name of this generator.

        Returns:
            Generator name (e.g., 'users', 'teams')
        """
        return self.__class__.__name__.replace("Generator", "").lower()

    def batch_insert(self, records: List[Any], table_name: Optional[str] = None) -> None:
        """Batch insert records efficiently.

        Args:
            records: List of model instances or dicts to insert
            table_name: Optional table name for dict-based inserts
        """
        if not records:
            return

        try:
            # Check if records are dicts (for association tables)
            if records and isinstance(records[0], dict):
                if not table_name:
                    raise ValueError("table_name required for dict-based inserts")
                from sqlalchemy import text
                # Build bulk insert statement
                columns = list(records[0].keys())
                placeholders = ", ".join([f":{col}" for col in columns])
                query = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})"
                self.db.execute(text(query), records)
                self.db.flush()
            else:
                # ORM objects - use add_all() to properly handle autoincrement fields
                self.db.add_all(records)
                self.db.flush()
            self.inserted_count += len(records)
        except Exception as e:
            self.logger.error(f"Batch insert failed for {self.get_name()}: {e}")
            self.db.rollback()
            raise

    def commit(self) -> None:
        """Commit current transaction."""
        try:
            self.db.commit()
            self.logger.debug(f"Committed {self.inserted_count} {self.get_name()} records")
        except Exception as e:
            self.logger.error(f"Commit failed for {self.get_name()}: {e}")
            self.db.rollback()
            raise

    def run(self) -> Dict[str, int]:
        """Run the generator and insert all records.

        Returns:
            Statistics dictionary with counts
        """
        self.logger.info(f"Starting {self.get_name()} generation...")

        batch = []
        commit_frequency = self.config.get("performance", {}).get("commit_frequency", 10000)

        for record in self.generate():
            batch.append(record)
            self.generated_count += 1

            if len(batch) >= self.batch_size:
                self.batch_insert(batch)
                batch = []

                # Periodic commit
                if self.inserted_count % commit_frequency == 0:
                    self.commit()

        # Insert remaining records
        if batch:
            self.batch_insert(batch)

        # Final commit
        self.commit()

        self.logger.info(f"Completed {self.get_name()} generation: {self.generated_count} records")

        return {
            "generated": self.generated_count,
            "inserted": self.inserted_count,
        }

    def get_scale_config(self, key: str, default: Any = None) -> Any:
        """Get a scale configuration value.

        Args:
            key: Configuration key under 'scale'
            default: Default value if not found

        Returns:
            Configuration value
        """
        return self.config.get("scale", {}).get(key, default)

    def get_realism_config(self, key: str, default: Any = None) -> Any:
        """Get a realism configuration value.

        Args:
            key: Configuration key under 'realism'
            default: Default value if not found

        Returns:
            Configuration value
        """
        return self.config.get("realism", {}).get(key, default)
