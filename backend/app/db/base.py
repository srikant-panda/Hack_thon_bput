"""Declarative base for SQLAlchemy models.

All CYBERGUARD tables live in the dedicated ``cyberguard`` schema on
PostgreSQL. SQLite (used by the test suite) has no schema support, so the
engine is built with ``schema_translate_map={"cyberguard": None}`` in
``app.db.session`` and every schema-qualified statement resolves to the
default schema there.
"""

from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.schema import MetaData

SCHEMA = "cyberguard"


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy mapped tables."""

    metadata = MetaData(schema=SCHEMA)
