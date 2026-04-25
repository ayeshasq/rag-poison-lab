# ☠️ RAG Poisoning Demo Lab

> An educational red-team lab demonstrating vector store poisoning attacks on RAG (Retrieval-Augmented Generation) systems — with defenses for each attack.

![Python](https://img.shields.io/badge/python-3.10+-blue) ![Free](https://img.shields.io/badge/cost-$0-green) ![License](https://img.shields.io/badge/license-MIT-yellow)

---

## What is RAG Poisoning?

RAG systems retrieve documents from a vector store to ground LLM responses in real data. If an attacker can influence *what gets stored* in that vector store, they can control *what the LLM says* — regardless of the original knowledge base.

This lab demonstrates 3 real attack classes with working code, then shows how to detect and block each one.

---

## Attacks Covered

| # | Attack | Technique | MITRE ATLAS |
|---|--------|-----------|-------------|
| 1 | **Direct Document Injection** | Attacker writes malicious docs to shared KB | AML.T0054 |
| 2 | **Indirect PDF Injection** | Hidden white-text payload in uploaded PDF | AML.T0054.002 |
| 3 | **Cross-Session Contamination** | Poisoned content from one session affects all users | AML.T0048 |

Each attack module includes: setup → baseline query → attack → poisoned query → cleanup.

---

## Tech Stack (100% Free)

| Component | Tool | Cost |
|-----------|------|------|
| LLM | [Groq](https://console.groq.com) — llama-3.3-70b | Free (1000 req/day) |
| Vector Store | ChromaDB — runs locally | Free forever |
| Embeddings | HuggingFace all-MiniLM-L6-v2 | Free, runs offline |
| Framework | LangChain | Open source |
| UI | Streamlit | Open source |

No credit card required anywhere.

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/yourusername/rag-poison-lab
cd rag-poison-lab
pip install -r requirements.txt

# 2. Configure (free Groq key at console.groq.com)
cp .env.example .env
# Edit .env and add your GROQ_API_KEY

# 3. Run all attacks via CLI
python run.py

# 4. Or launch the interactive UI
streamlit run ui/app.py

# Run a specific attack
python run.py --attack 1
python run.py --attack 2
python run.py --attack 3

# Demo the defense scanner
python run.py --defense
```

---

## Project Structure

```
rag-poison-lab/
├── core/
│   ├── embeddings.py       # Local HuggingFace embeddings (no API key)
│   ├── vector_store.py     # ChromaDB wrapper (local, persistent)
│   └── rag_engine.py       # RAG chain using Groq LLM
├── attacks/
│   ├── base_attack.py      # Abstract base class for all attacks
│   ├── attack1_direct_inject.py    # Direct KB injection
│   ├── attack2_pdf_poison.py       # Hidden-text PDF attack
│   └── attack3_cross_session.py   # Multi-user contamination
├── defense/
│   ├── scanner.py          # Regex + pattern injection detector
│   └── sanitizer.py        # Text cleaning before ingestion
├── data/
│   ├── clean_docs/         # Sample legitimate documents
│   └── poisoned_docs/      # Generated attack artifacts
├── ui/
│   └── app.py              # Streamlit interactive demo
├── run.py                  # CLI runner
├── requirements.txt
└── .env.example
```

---

## Defenses Demonstrated

Each attack is paired with specific mitigations:

- **Document provenance tracking** — trust flags on every ingested doc
- **Retrieval-time filtering** — only retrieve from trusted sources
- **Injection pattern scanner** — regex + heuristic pre-ingestion scan
- **Text sanitizer** — strips hidden characters and injection markers
- **Session namespace isolation** — separate vector collections per user

---

## Learning Resources

- [MITRE ATLAS](https://atlas.mitre.org/) — Adversarial ML threat matrix
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Garak](https://github.com/NVIDIA/garak) — LLM vulnerability scanner
- [LangChain Security](https://python.langchain.com/docs/security)

---

## Disclaimer

This project is for **educational and defensive security research only**. All attacks run against a local ChromaDB instance — no external systems are targeted. Use responsibly.

---

## Author

Built as a portfolio project demonstrating AI red-team skills.
Inspired by real-world RAG security incidents in enterprise deployments.
