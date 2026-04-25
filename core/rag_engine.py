"""
Core RAG engine — clean baseline.
Uses Groq (free) as the LLM, ChromaDB as the retriever,
local HuggingFace embeddings. Zero cost.
"""
import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from core.vector_store import get_vector_store

load_dotenv()

SYSTEM_PROMPT = """You are a helpful assistant. Answer the user's question 
using ONLY the context provided below. If the context doesn't contain 
the answer, say "I don't have enough information."

Context:
{context}
"""


def get_llm():
    return ChatGroq(
        api_key=os.getenv("GROQ_API_KEY"),
        model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
        temperature=0,
    )


def format_docs(docs):
    return "\n\n---\n\n".join(doc.page_content for doc in docs)


def build_rag_chain(collection_name: str = "rag_lab"):
    """Build a LangChain RAG chain over a ChromaDB collection."""
    store = get_vector_store(collection_name)
    retriever = store.as_retriever(search_kwargs={"k": 4})
    llm = get_llm()

    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", "{question}"),
    ])

    chain = (
        {"context": retriever | format_docs, "question": RunnablePassthrough()}
        | prompt
        | llm
        | StrOutputParser()
    )
    return chain


def query_rag(question: str, collection_name: str = "rag_lab",
              return_sources: bool = False):
    """
    Query the RAG system. Returns answer string, or (answer, sources) tuple.
    """
    store = get_vector_store(collection_name)
    retriever = store.as_retriever(search_kwargs={"k": 4})

    # Retrieve docs
    docs = retriever.invoke(question)

    # Build chain and run
    chain = build_rag_chain(collection_name)
    answer = chain.invoke(question)

    if return_sources:
        return answer, docs
    return answer
