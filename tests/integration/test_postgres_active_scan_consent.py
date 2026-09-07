"""The three consent columns survive a real round trip, and a withdrawal persists.

The migration itself is covered from two directions already and neither is repeated
here: the suite's schema is built by `alembic upgrade head` (see `conftest`), so every
assertion below runs against production's DDL, and `test_schema_matches_models.py`
compares tables, columns, constraints and indexes in both directions. What that pair
does not cover is the upsert's `SET` clause — a column present in the schema, mapped on
the model, and simply left out of `on_conflict_do_update` would pass both.
"""

from datetime import UTC, datetime

from verion.modules.projects.adapters.outbound.db.repository import (
    PostgresProjectRepository,
    PostgresScannerConfigRepository,
)
from verion.modules.projects.domain.project import Project
from verion.modules.projects.domain.scanner_config import ScannerConfig
from verion.shared_kernel.scanner_tools import ScannerTool

_TARGET = "https://staging.acme.example"
_GRANTED_AT = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


def _project() -> Project:
    return Project(
        id="project-1",
        owner_id="owner-1",
        name="Verion",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _config(**overrides) -> ScannerConfig:
    base = {
        "id": "config-1",
        "project_id": "project-1",
        "enabled_tools": (ScannerTool.ZAP,),
        "zap_target_url": _TARGET,
        "updated_at": datetime(2026, 8, 27, tzinfo=UTC),
        "active_scan_consent_target": _TARGET,
        "active_scan_consent_granted_at": _GRANTED_AT,
        "active_scan_consent_granted_by": "owner-1",
    }
    return ScannerConfig(**{**base, **overrides})


async def test_round_trips_a_granted_consent_through_postgres(db_session):
    await PostgresProjectRepository(db_session).add(_project())
    repository = PostgresScannerConfigRepository(db_session)
    config = _config()

    await repository.upsert(config)

    stored = await repository.get_by_project_id("project-1")
    assert stored == config
    assert stored.active_scan_consent_in_force is True


async def test_a_withdrawal_clears_the_columns_in_the_database(db_session):
    """The upsert's `SET` clause, which is the half no schema comparison reaches. A
    withdrawal that is not written leaves the previous grant in the row, and the next
    read reports consent the owner revoked."""
    await PostgresProjectRepository(db_session).add(_project())
    repository = PostgresScannerConfigRepository(db_session)
    await repository.upsert(_config())

    await repository.upsert(
        _config(
            active_scan_consent_target=None,
            active_scan_consent_granted_at=None,
            active_scan_consent_granted_by=None,
        )
    )

    stored = await repository.get_by_project_id("project-1")
    assert stored.active_scan_consent_target is None
    assert stored.active_scan_consent_granted_at is None
    assert stored.active_scan_consent_granted_by is None
    assert stored.active_scan_consent_in_force is False


async def test_a_repointed_target_persists_the_stale_grant_and_reads_as_not_in_force(db_session):
    """ADR-0024 decision 3 across a real round trip. The row keeps the grant — this is
    not a delete — and the verdict is false because the two values no longer agree."""
    await PostgresProjectRepository(db_session).add(_project())
    repository = PostgresScannerConfigRepository(db_session)
    await repository.upsert(_config())

    await repository.upsert(_config(zap_target_url="https://acme.example"))

    stored = await repository.get_by_project_id("project-1")
    assert stored.active_scan_consent_target == _TARGET
    assert stored.zap_target_url == "https://acme.example"
    assert stored.active_scan_consent_in_force is False
