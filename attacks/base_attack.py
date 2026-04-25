"""
Base class for all attack modules.
Each attack must implement: setup(), execute(), cleanup(), explain().
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime


@dataclass
class AttackResult:
    attack_name: str
    success: bool
    baseline_answer: str
    poisoned_answer: str
    injected_payload: str
    retrieved_docs: list
    timestamp: str = None
    notes: str = ""

    def __post_init__(self):
        self.timestamp = datetime.now().isoformat()

    def summary(self) -> dict:
        return {
            "attack": self.attack_name,
            "success": self.success,
            "baseline": self.baseline_answer[:200],
            "poisoned": self.poisoned_answer[:200],
            "payload_preview": self.injected_payload[:150],
            "timestamp": self.timestamp,
        }


class BaseAttack(ABC):
    name: str = "Base Attack"
    description: str = ""
    collection_name: str = "rag_lab_attack"

    @abstractmethod
    def setup(self):
        """Load clean documents into the vector store."""
        pass

    @abstractmethod
    def execute(self, target_question: str) -> AttackResult:
        """Run the attack and return a result."""
        pass

    @abstractmethod
    def cleanup(self):
        """Reset the vector store after demo."""
        pass

    @abstractmethod
    def explain(self) -> str:
        """Return a plain-English explanation of this attack."""
        pass

    @abstractmethod
    def mitigation(self) -> str:
        """Return how to defend against this attack."""
        pass
