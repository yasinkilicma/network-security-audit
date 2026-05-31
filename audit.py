#!/usr/bin/env python3
"""
audit.py – Hauptskript des Netzwerk-Sicherheits-Audit-Tools
=============================================================
Dieses Skript ist der Einstiegspunkt des Tools. Es liest die
Kommandozeilenargumente, koordiniert die einzelnen Prüfmodule
und gibt am Ende einen konsolidierten Sicherheitsbericht aus.

Aufrufbeispiele:
    python audit.py --target 192.168.1.1
    python audit.py --target 192.168.1.0/24 --ports 1-1024 --output html
    python audit.py --target 10.0.0.1 --output json
"""

import argparse
import sys
from datetime import datetime

from modules.port_scanner import PortScanner
from modules.service_checker import ServiceChecker
from modules.cis_benchmark import CISBenchmark
from modules.report_generator import ReportGenerator


def parse_argumente() -> argparse.Namespace:
    """
    Liest und validiert die Kommandozeilenargumente.

    Gibt ein Namespace-Objekt mit allen Parametern zurück.
    Bei fehlenden Pflichtfeldern oder ungültigen Werten wird
    automatisch eine Hilfe-Nachricht angezeigt und das
    Programm beendet.
    """
    parser = argparse.ArgumentParser(
        description="Netzwerk-Sicherheits-Audit-Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  %(prog)s --target 192.168.1.1
  %(prog)s --target 192.168.1.1 --ports 1-1024
  %(prog)s --target 192.168.1.0/24 --output html
  %(prog)s --target 10.0.0.1 --ports 22,80,443 --output json
        """
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Ziel-IP-Adresse oder CIDR-Netzwerk (z.B. 192.168.1.1 oder 192.168.1.0/24)"
    )
    parser.add_argument(
        "--ports", "-p",
        default="1-1024",
        help="Port-Bereich oder kommaseparierte Liste (Standard: 1-1024)"
    )
    parser.add_argument(
        "--output", "-o",
        choices=["text", "json", "html"],
        default="text",
        help="Ausgabeformat des Berichts (Standard: text)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Verbindungs-Timeout pro Port in Sekunden (Standard: 1.0)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Anzahl paralleler Scan-Threads (Standard: 100)"
    )

    return parser.parse_args()


def hauptprogramm() -> None:
    """
    Koordiniert den gesamten Audit-Ablauf in drei Phasen:

      Phase 1 – Port-Scanning:
        Der PortScanner prüft alle angegebenen Ports auf TCP-Erreichbarkeit.
        Offene Ports werden mit Dienst-Bezeichnung gespeichert.

      Phase 2 – Dienst-Analyse:
        Der ServiceChecker versucht für jeden offenen Port via Banner-Grabbing
        die genaue Software-Version zu ermitteln und bewertet diese.

      Phase 3 – CIS-Benchmark:
        Der CISBenchmark gleicht die Ergebnisse gegen bekannte
        Sicherheitsrichtlinien ab und erstellt priorisierte Befunde.

    Abschließend erzeugt der ReportGenerator den Bericht im
    gewünschten Format (text/json/html).
    """
    args = parse_argumente()

    # Kopfzeile für den Audit-Start
    print(f"\n{'='*60}")
    print(f"  NETZWERK-SICHERHEITS-AUDIT")
    print(f"  Ziel:        {args.target}")
    print(f"  Ports:       {args.ports}")
    print(f"  Zeitstempel: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    print(f"{'='*60}\n")

    # --- Phase 1: Port-Scanning ---
    print("[1/3] Starte Port-Scanning...")
    scanner = PortScanner(timeout=args.timeout, threads=args.threads)
    scan_ergebnisse = scanner.scan(args.target, args.ports)

    if not scan_ergebnisse:
        print("  -> Keine offenen Ports gefunden. Audit abgeschlossen.")
        sys.exit(0)

    print(f"  -> {len(scan_ergebnisse)} offene Ports gefunden.")

    # --- Phase 2: Dienst-Analyse ---
    print("[2/3] Analysiere erkannte Dienste...")
    checker = ServiceChecker(timeout=args.timeout)
    dienst_ergebnisse = checker.pruefen(scan_ergebnisse)
    print(f"  -> {len(dienst_ergebnisse)} Dienste analysiert.")

    # --- Phase 3: CIS-Benchmark ---
    print("[3/3] Führe CIS-Benchmark-Prüfungen durch...")
    benchmark = CISBenchmark()
    benchmark_ergebnisse = benchmark.pruefen(scan_ergebnisse, dienst_ergebnisse)
    print(f"  -> {len(benchmark_ergebnisse)} Befunde identifiziert.\n")

    # Gesamtbericht zusammenstellen
    bericht = {
        "meta": {
            "ziel": args.target,
            "ports": args.ports,
            "zeitstempel": datetime.now().isoformat(),
            "tool": "network-security-audit",
        },
        "port_scan": scan_ergebnisse,
        "dienste": dienst_ergebnisse,
        "cis_benchmark": benchmark_ergebnisse,
    }

    # Bericht ausgeben
    generator = ReportGenerator()
    generator.erstellen(bericht, format=args.output)


if __name__ == "__main__":
    hauptprogramm()
