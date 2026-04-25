"""
ChromaDB vector store wrapper.
Local, persistent, free — no cloud needed.
"""
import os
import chromadb
from langchain_community.vectorstores import Chroma
from core.embeddings import get_embeddings

CHROMA_PATH = os.getenv("CHROMA_DB_PATH", "./data/chroma_db")


def get_vector_store(collection_name: str = "rag_lab") -> Chroma:
    """Get or create a ChromaDB collection."""
    embeddings = get_embeddings()
    return Chroma(
        collection_name=collection_name,
        embedding_function=embeddings,
        persist_directory=CHROMA_PATH,
    )


def reset_vector_store(collection_name: str = "rag_lab"):
    """Wipe a collection — useful between attack demos."""
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    try:
        client.delete_collection(collection_name)
        print(f"[reset] Collection '{collection_name}' wiped.")
    except Exception:
        print(f"[reset] Collection '{collection_name}' did not exist.")


def add_documents(texts: list[str], metadatas: list[dict] = None,
                  collection_name: str = "rag_lab") -> Chroma:
    """Add plain text documents to the vector store."""
    from langchain.schema import Document
    store = get_vector_store(collection_name)
    docs = [
        Document(page_content=t, metadata=metadatas[i] if metadatas else {"source": f"doc_{i}"})
        for i, t in enumerate(texts)
    ]
    store.add_documents(docs)
    return store


def similarity_search(query: str, k: int = 4,
                      collection_name: str = "rag_lab") -> list:
    """Retrieve top-k relevant documents for a query."""
    store = get_vector_store(collection_name)
    return store.similarity_search(query, k=k)
