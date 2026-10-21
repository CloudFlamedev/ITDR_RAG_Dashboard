import pytest
from app.services.document_builder import DocumentBuilderService, compute_content_hash


def test_compute_content_hash():
    text1 = "Test content for hashing"
    text2 = "Test content for hashing"
    text3 = "Different content"

    assert compute_content_hash(text1) == compute_content_hash(text2)
    assert compute_content_hash(text1) != compute_content_hash(text3)
    assert len(compute_content_hash(text1)) == 64  # SHA-256 length


def test_build_knowledge_documents(db_session):
    builder = DocumentBuilderService(db_session)
    drafts = builder.build_all_knowledge_documents(identity_only_techniques=True)
    assert len(drafts) > 0

    # Verify drafted fields
    sample = drafts[0]
    assert sample.chunk_id is not None
    assert sample.source_kind in ["attack", "d3fend", "feed"]
    assert sample.content is not None
    assert sample.content_hash == compute_content_hash(sample.content)
    assert isinstance(sample.metadata, dict)
