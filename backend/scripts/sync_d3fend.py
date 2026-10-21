#!/usr/bin/env python3
"""
CLI script to sync MITRE D3FEND ontology JSON data into PostgreSQL.
Usage:
    python scripts/sync_d3fend.py [--file PATH_TO_D3FEND_JSON]
"""
import sys
import os
import argparse
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.services.d3fend_ingestion_service import D3fendIngestionService

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sync_d3fend")


def main():
    parser = argparse.ArgumentParser(description="Sync MITRE D3FEND ontology data")
    parser.add_argument("--file", type=str, default=None, help="Path to d3fend.json file")
    args = parser.parse_args()

    settings = get_settings()
    file_path = args.file or settings.D3FEND_FILE

    if not os.path.exists(file_path):
        logger.error(f"D3FEND file not found: {file_path}")
        sys.exit(1)

    db = SessionLocal()
    try:
        service = D3fendIngestionService(db)
        stats = service.ingest_from_file(file_path)
        logger.info(f"D3FEND sync successfully completed: {stats}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
