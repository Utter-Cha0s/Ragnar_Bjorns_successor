import os
from pathlib import Path

from db_manager import DatabaseManager


def _build_db(tmp_path: Path) -> DatabaseManager:
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "ragnar.db"
    return DatabaseManager(db_path=str(db_path), currentdir=str(tmp_path))


def test_sanitize_hostname_collapses_aliases(tmp_path):
    db = _build_db(tmp_path)
    dirty = "; ; ; iPad; iPad ; ;"
    assert db.sanitize_hostname(dirty) == "iPad"


def test_sanitize_all_hostnames_cleans_existing_rows(tmp_path):
    db = _build_db(tmp_path)
    mac = "aa:bb:cc:dd:ee:01"
    dirty = "; ; Watch; Watch"
    with db.get_connection() as conn:
        conn.execute("INSERT INTO hosts (mac, hostname) VALUES (?, ?)", (mac, dirty))
    db.sanitize_all_hostnames()
    cleaned = db.get_host_by_mac(mac)
    assert cleaned["hostname"] == "Watch"


def test_upsert_host_persists_sanitized_hostname(tmp_path):
    db = _build_db(tmp_path)
    mac = "aa:bb:cc:dd:ee:ff"
    db.upsert_host(mac=mac, ip="192.168.1.50", hostname="; ; ; ; Nest-Audio ; Nest-Audio")
    host = db.get_host_by_mac(mac)
    assert host["hostname"] == "Nest-Audio"
