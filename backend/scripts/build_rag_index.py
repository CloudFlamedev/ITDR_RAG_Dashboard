#!/usr/bin/env python3
"""
CLI script to build or incrementally update the RAG vector index in PostgreSQL.
Usage:
    python scripts/build_rag_index.py [--identity-only] [--batch-size 32]
"""
import sys
import os
import argparse
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.session import SessionLocal
from app.services.document_builder import DocumentBuilderService
from app.services.embedding_service import EmbeddingService
from app.services.vector_store_service import VectorStoreService

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("build_rag_index")


def main():
    parser = argparse.ArgumentParser(description="Build / update RAG knowledge index in PostgreSQL")
    parser.add_argument("--identity-only", action="store_true", help="Only index identity-relevant techniques")
    parser.add_argument("--batch-size", type=int, default=32, help="Embedding batch size")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        doc_builder = DocumentBuilderService(db)
        embedding_service = EmbeddingService()
        vector_store = VectorStoreService(db, embedding_service)

        logger.info("Compiling semantic knowledge documents...")
        drafts = doc_builder.build_all_knowledge_documents(identity_only_techniques=args.identity_only)

        logger.info(f"Syncing {len(drafts)} documents to pgvector store...")
        stats = vector_store.sync_documents(drafts, batch_size=args.batch_size)

        logger.info(f"RAG Indexing complete: {stats}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
