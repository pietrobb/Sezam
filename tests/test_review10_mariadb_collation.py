"""Review 8595ec1 (low): CI tested MariaDB 10.11, compose ran 11.8 with another collation.

The schema named only the character set, so a table's collation was whatever
the server defaulted to: utf8mb4_general_ci on 10.11 (CI), utf8mb4_uca1400_ai_ci
on 11.8 (compose). Usernames and ids compared and deduplicated differently in
production than in the tests. The schema now names the collation, and CI runs
the image compose deploys.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from server.app import database
from tests.test_review2_server_mariadb import mariadb  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parent.parent
COLLATION = "utf8mb4_uca1400_ai_ci"


def _image(text: str) -> str:
    return re.search(r"image:\s*(mariadb:\S+)", text).group(1)


def test_ci_runs_the_mariadb_image_compose_deploys():
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    ci = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    assert _image(ci) == _image(compose)


def test_every_utf8mb4_table_names_its_collation():
    tables = re.findall(r"\) ENGINE=InnoDB DEFAULT CHARSET=(\w+)([^;]*);", database.SCHEMA_SQL)
    assert tables
    for charset, rest in tables:
        if charset == "utf8mb4":
            assert f"COLLATE={COLLATION}" in rest, rest


@pytest.mark.asyncio
async def test_tables_get_the_pinned_collation_whatever_the_server_default(mariadb):  # noqa: F811
    async with mariadb.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT TABLE_NAME, TABLE_COLLATION FROM information_schema.TABLES "
                "WHERE TABLE_SCHEMA = DATABASE()"
            )
            rows = await cur.fetchall()
    assert rows
    for name, collation in rows:
        if collation.startswith("utf8mb4"):
            assert collation == COLLATION, name
