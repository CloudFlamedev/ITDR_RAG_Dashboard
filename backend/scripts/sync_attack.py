#!/usr/bin/env python3
"""
CLI script to sync MITRE ATT&CK Enterprise STIX 2.1 data into PostgreSQL.
Usage:
    python scripts/sync_attack.py [--file PATH_TO_STIX_JSON]
"""
import sys
import os
import argparse
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.services.attack_ingestion_service import AttackIngestionService

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sync_attack")


def main():
    parser = argparse.ArgumentParser(description="Sync MITRE ATT&CK Enterprise STIX data")
    parser.add_argument("--file", type=str, default=None, help="Path to enterprise-attack.json file")
    args = parser.parse_args()

    settings = get_settings()
    file_path = args.file or settings.ATTACK_STIX_FILE

    if not os.path.exists(file_path):
        logger.error(f"ATT&CK STIX file not found: {file_path}")
        sys.exit(1)

    db = SessionLocal()
    try:
        service = AttackIngestionService(db)
        stats = service.ingest_from_file(file_path)
        logger.info(f"Sync successfully completed: {stats}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
