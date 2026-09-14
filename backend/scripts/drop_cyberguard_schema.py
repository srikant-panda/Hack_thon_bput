#!/usr/bin/env python3
"""Drop the full cyberguard schema — policies, tables, and everything else.

DESTRUCTIVE. This deletes the entire `cyberguard` schema: every RLS policy,
every table, every index, and all data. It exists for full-reset workflows
(see docs/RUNBOOK.md section 4); after running it, rebuild with:

    uv run alembic upgrade head

Safety features:
- Connects with MIGRATION_DATABASE_URL (the `postgres` migration role). The
  app role (`cyberguard_api`) can neither drop the schema nor the stale
  `public.alembic_version` — the script fails loudly when it detects it.
- Refuses to run unless `--yes` is passed or the target is interactively
  confirmed.
- `--dry-run` prints exactly what would be deleted without touching anything.
- `--keep-alembic-version` leaves the migration bookkeeping table in place.

Run from the backend directory:
    uv run python scripts/drop_cyberguard_schema.py --dry-run
    uv run python scripts/drop_cyberguard_schema.py --yes
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from app.core.config import get_settings  # noqa: E402

SCHEMA = "cyberguard"


def _migration_engine():
    settings = get_settings()
    url = (settings.MIGRATION_DATABASE_URL or settings.DATABASE_URL).strip()
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if "postgresql" not in url:
        print(
            f"✋ Refusing to run: MIGRATION_DATABASE_URL/DATABASE_URL is not PostgreSQL "
            f"(got a {url.split('://')[0]} URL). This script only targets Postgres."
        )
        sys.exit(2)
    return create_async_engine(url)


async def _gather_state(conn) -> dict:
    """Everything the plan report needs; read-only."""
    state: dict = {}
    state["role"] = (await conn.execute(text("select current_user"))).scalar()
    state["schema_exists"] = (
        await conn.execute(
            text("select count(*) from pg_namespace where nspname = :s"), {"s": SCHEMA}
        )
    ).scalar() > 0
    state["tables"] = (
        await conn.execute(
            text(
                "select tablename from pg_tables where schemaname = :s order by tablename"
            ),
            {"s": SCHEMA},
        )
    ).scalars().all()
    state["policies"] = (
        await conn.execute(
            text(
                "select tablename, policyname from pg_policies where schemaname = :s "
                "order by tablename, policyname"
            ),
            {"s": SCHEMA},
        )
    ).all()
    state["has_alembic_version"] = (
        await conn.execute(
            text(
                "select count(*) from pg_tables where schemaname = 'public' "
                "and tablename = 'alembic_version'"
            )
        )
    ).scalar() > 0
    state["alembic_revision"] = None
    if state["has_alembic_version"]:
        try:
            state["alembic_revision"] = (
                await conn.execute(text("select version_num from public.alembic_version limit 1"))
            ).scalar()
        except Exception:  # noqa: BLE001 - table may be owned by another role / unreadable
            pass
    state["owns_schema"] = (
        await conn.execute(
            text(
                "select pg_get_userbyid(nspowner) = current_user "
                "from pg_namespace where nspname = :s"
            ),
            {"s": SCHEMA},
        )
    ).scalar() if state["schema_exists"] else True
    return state


def _print_plan(state: dict) -> None:
    print(f"Connected as role          : {state['role']}")
    print(f"Schema '{SCHEMA}' exists   : {state['schema_exists']}")
    if state["schema_exists"]:
        print(f"Tables to be dropped       : {len(state['tables'])}")
        for t in state["tables"]:
            n = sum(1 for p in state["policies"] if p[0] == t)
            print(f"  - {t} ({n} RLS policies)")
        print(f"RLS policies to be dropped : {len(state['policies'])}")
    print(f"public.alembic_version     : "
          f"{'present (revision ' + str(state['alembic_revision']) + ') — will be dropped' if state['has_alembic_version'] else 'absent'}")


async def _drop(conn, state: dict, keep_alembic_version: bool) -> None:
    # 1. Policies explicitly (DROP SCHEMA CASCADE would remove them with the
    #    tables anyway, but doing it first makes the deletion legible and
    #    leaves nothing policy-shaped behind if a later step is interrupted).
    for tablename, policyname in state["policies"]:
        await conn.execute(
            text(f'DROP POLICY IF EXISTS "{policyname}" ON {SCHEMA}."{tablename}"')
        )
    print(f"dropped {len(state['policies'])} RLS policies")

    # 2. Tables one by one (readable audit trail), then the schema itself —
    #    CASCADE catches anything created after the state snapshot.
    for tablename in state["tables"]:
        await conn.execute(text(f'DROP TABLE IF EXISTS {SCHEMA}."{tablename}" CASCADE'))
    print(f"dropped {len(state['tables'])} tables")

    await conn.execute(text(f'DROP SCHEMA IF EXISTS "{SCHEMA}" CASCADE'))
    print(f"dropped schema '{SCHEMA}'")

    # 3. Migration bookkeeping (otherwise `alembic upgrade head` would think
    #    the old revision is still applied).
    if state["has_alembic_version"] and not keep_alembic_version:
        await conn.execute(text("DROP TABLE IF EXISTS public.alembic_version"))
        print("dropped public.alembic_version (migration bookkeeping reset)")


async def main_async(args: argparse.Namespace) -> None:
    engine = _migration_engine()
    try:
        async with engine.connect() as conn:
            state = await _gather_state(conn)

            if state["role"] == "cyberguard_api":
                print(
                    "✋ Refusing to run: connected as the application role "
                    "'cyberguard_api' (NOBYPASSRLS, non-owner). Set "
                    "MIGRATION_DATABASE_URL to the postgres migration role and retry."
                )
                sys.exit(2)
            if state["schema_exists"] and not state["owns_schema"]:
                print(
                    f"✋ Refusing to run: role '{state['role']}' does not own the "
                    f"'{SCHEMA}' schema — it cannot drop it."
                )
                sys.exit(2)

            _print_plan(state)

            if args.dry_run:
                print("\n--dry-run: nothing was deleted.")
                return
            if not state["schema_exists"] and not state["has_alembic_version"]:
                print("\nNothing to delete — schema and bookkeeping already absent.")
                return

            if not args.yes:
                answer = input(
                    f"\nType 'DROP {SCHEMA}' to permanently delete the schema, all tables, "
                    "policies and data: "
                )
                if answer.strip() != f"DROP {SCHEMA}":
                    print("Aborted — nothing was deleted.")
                    return

            # End the autobegun read transaction from the state snapshot so
            # the destructive work runs in one clean transaction.
            await conn.rollback()
            async with conn.begin():
                await _drop(conn, state, args.keep_alembic_version)

            # Post-state verification.
            after = await _gather_state(conn)
            print(
                "\n✔ Done. "
                f"Schema exists: {after['schema_exists']} | "
                f"tables: {len(after['tables'])} | "
                f"policies: {len(after['policies'])} | "
                f"public.alembic_version present: {after['has_alembic_version']}"
            )
            print("Rebuild with:  uv run alembic upgrade head")
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Drop the full cyberguard schema (policies + tables + data).")
    parser.add_argument("--yes", action="store_true", help="skip the interactive confirmation")
    parser.add_argument("--dry-run", action="store_true", help="show what would be deleted, delete nothing")
    parser.add_argument(
        "--keep-alembic-version",
        action="store_true",
        help="leave public.alembic_version in place (NOT recommended before re-baselining)",
    )
    asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    main()
