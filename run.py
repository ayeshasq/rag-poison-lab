"""
RAG Poisoning Demo Lab — CLI Runner
=====================================
Run all attacks or a specific one from the command line.
Usage:
    python run.py                  # run all attacks
    python run.py --attack 1       # run attack 1 only
    python run.py --attack 2 --keep  # keep vector store after demo
    python run.py --defense        # demo the defense scanner
"""
import argparse
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

load_dotenv()
console = Console()


def run_attack(attack_class, keep=False):
    attack = attack_class()
    console.print(Panel(
        f"[bold]{attack.name}[/bold]\n\n{attack.description}\n\n"
        f"[yellow]How it works:[/yellow] {attack.explain()[:200]}...",
        title="[red]ATTACK[/red]", border_style="red"
    ))

    attack.setup()
    result = attack.execute()

    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("", style="bold cyan", width=15)
    table.add_column("Result", width=70)
    table.add_row("Attack", result.attack_name)
    table.add_row("Success", "[red]YES[/red]" if result.success else "[green]NO[/green]")
    table.add_row("Baseline answer", result.baseline_answer[:200])
    table.add_row("Poisoned answer", f"[red]{result.poisoned_answer[:200]}[/red]")
    table.add_row("Payload preview", result.injected_payload[:150])
    console.print(table)

    console.print(Panel(
        attack.mitigation(),
        title="[green]DEFENSE — How to fix this[/green]",
        border_style="green"
    ))

    if not keep:
        attack.cleanup()

    return result


def demo_defense():
    from defense.scanner import scan_text
    from attacks.attack1_direct_inject import POISON_PAYLOAD
    from attacks.attack3_cross_session import ATTACKER_PAYLOAD

    console.print(Panel("Testing injection scanner against known payloads", title="[green]DEFENSE DEMO[/green]", border_style="green"))

    for label, text in [
        ("Clean document", "Our refund policy allows returns within 30 days of purchase."),
        ("Attack 1 payload", POISON_PAYLOAD),
        ("Attack 3 payload", ATTACKER_PAYLOAD),
    ]:
        result = scan_text(text)
        color = "red" if result.is_suspicious else "green"
        console.print(f"\n[bold]{label}[/bold]")
        console.print(f"[{color}]{result}[/{color}]")


def main():
    parser = argparse.ArgumentParser(description="RAG Poisoning Demo Lab")
    parser.add_argument("--attack", type=int, choices=[1, 2, 3], help="Run a specific attack (1-3)")
    parser.add_argument("--keep", action="store_true", help="Don't clean up vector store after demo")
    parser.add_argument("--defense", action="store_true", help="Demo the defense scanner")
    args = parser.parse_args()

    console.print(Panel(
        "[bold red]RAG Poisoning Demo Lab[/bold red]\n"
        "Educational demonstration of vector store poisoning attacks.\n"
        "All attacks run against a local ChromaDB — no external services harmed.",
        border_style="red"
    ))

    if args.defense:
        demo_defense()
        return

    from attacks.attack1_direct_inject import DirectInjectionAttack
    from attacks.attack2_pdf_poison import PDFPoisonAttack
    from attacks.attack3_cross_session import CrossSessionAttack

    attack_map = {1: DirectInjectionAttack, 2: PDFPoisonAttack, 3: CrossSessionAttack}

    if args.attack:
        run_attack(attack_map[args.attack], keep=args.keep)
    else:
        results = []
        for cls in attack_map.values():
            results.append(run_attack(cls, keep=args.keep))
            console.rule()

        # Summary
        summary = Table(title="Attack Summary", box=box.ROUNDED)
        summary.add_column("Attack")
        summary.add_column("Success")
        for r in results:
            summary.add_row(r.attack_name, "[red]✓[/red]" if r.success else "[green]✗[/green]")
        console.print(summary)


if __name__ == "__main__":
    main()
