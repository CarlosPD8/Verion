"""The migrated schema and `Base.metadata` must agree.

The suite's schema is built by Alembic (see `conftest.migrated_schema`), so every
other test in this tree already asserts against the schema production runs. That
covers a constraint some test exercises. This file covers the one nothing
exercises: a `CHECK` declared on a model and forgotten in its migration would
otherwise exist in neither place and be asserted nowhere at all.

**Names, not DDL, and that is the whole design.** Comparing rendered SQL text
would fail on Postgres's own normalization (`(match_count >= 1)` vs
`match_count >= 1`) and turn into a test people edit rather than believe. Names
work here because this project already requires every UNIQUE and CHECK
constraint to carry an explicit `uq_…`/`ck_…` name so `ON CONFLICT` can target
it — a convention that exists for another reason and happens to make this cheap.

**Why not `alembic.autogenerate.compare_metadata`,** which is the obvious tool:
it compares tables, columns, types, nullability, indexes and unique constraints
but **not CHECK constraints**, which is precisely the failure being guarded
against — M4.3 alone adds six of them. It would report confident agreement on
everything except the part that matters most.

Deliberately out of scope, so the limits are stated rather than assumed: column
types, nullability, and indexes. Primary and foreign keys are compared only when
explicitly named, because Postgres auto-names the rest (`<table>_pkey`,
`<table>_<col>_fkey`) and those names appear in no model.
"""

from sqlalchemy import inspect
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine

from verion.platform.db import Base


def _reflect(connection: Connection) -> dict[str, tuple[set[str], set[str]]]:
    inspector = inspect(connection)
    reflected: dict[str, tuple[set[str], set[str]]] = {}
    for table_name in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns(table_name)}
        constraints = {
            constraint["name"]
            for constraint in inspector.get_check_constraints(table_name)
            if constraint["name"] is not None
        } | {
            constraint["name"]
            for constraint in inspector.get_unique_constraints(table_name)
            if constraint["name"] is not None
        }
        reflected[table_name] = (columns, constraints)
    return reflected


async def test_every_declared_table_column_and_named_constraint_exists_in_the_migrated_schema(
    engine: AsyncEngine,
):
    async with engine.connect() as connection:
        reflected = await connection.run_sync(_reflect)

    declared_tables = set(Base.metadata.tables)
    # alembic_version is the migration bookkeeping table; no model declares it
    # and none should.
    reflected_tables = set(reflected) - {"alembic_version"}

    # Compared in BOTH directions, and the second direction is not symmetry for
    # its own sake — it is what stops this whole file going vacuous. `Base
    # .metadata` holds only the tables whose model modules have been imported, so
    # a comparison that checked "declared ⊆ migrated" would pass trivially if the
    # conftest's import list ever fell behind. Verified by mutation: an early
    # draft omitted this and a CHECK added to a model, absent from the migration,
    # went undetected.
    assert declared_tables == reflected_tables, (
        f"The models and the migrated schema disagree on which tables exist. "
        f"Only in the models: {sorted(declared_tables - reflected_tables)} — a model with no "
        f"migration, or one on a second declarative base, which Alembic's env.py never sees "
        f"(rule 8). Only in the migrations: {sorted(reflected_tables - declared_tables)} — a "
        f"table nothing declares, or a model module missing from this tree's conftest import "
        f"list, which would silently narrow every assertion below."
    )

    for name, table in sorted(Base.metadata.tables.items()):
        reflected_columns, reflected_constraints = reflected[name]

        declared_columns = {column.name for column in table.columns}
        assert declared_columns == reflected_columns, (
            f"Table '{name}': the model and the migration disagree on columns. "
            f"Only in the model: {sorted(declared_columns - reflected_columns)}. "
            f"Only in the migration: {sorted(reflected_columns - declared_columns)}."
        )

        declared_constraints = {
            constraint.name
            for constraint in table.constraints
            # A str name means somebody named it deliberately. SQLAlchemy leaves
            # unnamed primary and foreign keys carrying a sentinel rather than a
            # string, and those are exactly the ones Postgres auto-names.
            if isinstance(constraint.name, str)
        }
        assert declared_constraints == reflected_constraints, (
            f"Table '{name}': the model and the migration disagree on named constraints. "
            f"Only in the model: {sorted(declared_constraints - reflected_constraints)} — "
            f"these would pass every test that builds rows through the domain and fail in "
            f"production. Only in the migration: "
            f"{sorted(reflected_constraints - declared_constraints)}."
        )
