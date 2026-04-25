"""
Local embeddings using HuggingFace sentence-transformers.
100% free, no API key, runs offline.
"""
from langchain_community.embeddings import HuggingFaceEmbeddings

def get_embeddings():
    """
    Returns a local embedding model.
    First run downloads ~90MB model automatically.
    Model: all-MiniLM-L6-v2 — fast, good quality, free forever.
    """
    return HuggingFaceEmbeddings(
        model_name="all-MiniLM-L6-v2",
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True},
    )
