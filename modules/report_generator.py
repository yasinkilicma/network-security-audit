"""
report_generator.py – Berichterstattung
========================================
Dieses Modul erzeugt den abschließenden Sicherheitsbericht in drei
verschiedenen Formaten:

  text  – Farbige Terminal-Ausgabe (ANSI-Escape-Codes, Colorama)
  json  – Maschinenlesbares JSON-Dokument (für SIEM-Integration)
  html  – Interaktiver HTML-Bericht mit Bootstrap 5

Gesamtrisiko-Berechnung:
  Das Gesamtrisiko wird aus den schwersten Befunden abgeleitet:
  - Mindestens ein KRITISCH-Befund → Gesamtrisiko: KRITISCH
  - Mindestens ein HOCH-Befund     → Gesamtrisiko: HOCH
  - Mindestens ein MITTEL-Befund   → Gesamtrisiko: MITTEL
  - Nur NIEDRIG-Befunde            → Gesamtrisiko: NIEDRIG
  - Keine Befunde                  → Gesamtrisiko: BESTANDEN
"""

import json
import os
from datetime import datetime
from typing import Dict, Any

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    FARBEN_VERFUEGBAR = True
except ImportError:
    # Colorama nicht installiert – keine Farben, aber funktionsfähig
    FARBEN_VERFUEGBAR = False


# ANSI-Farbcodes für Terminal-Ausgabe
FARBE = {
    "KRITISCH": Fore.RED + Style.BRIGHT    if FARBEN_VERFUEGBAR else "",
    "HOCH":     Fore.RED                   if FARBEN_VERFUEGBAR else "",
    "MITTEL":   Fore.YELLOW                if FARBEN_VERFUEGBAR else "",
    "NIEDRIG":  Fore.CYAN                  if FARBEN_VERFUEGBAR else "",
    "OK":       Fore.GREEN                 if FARBEN_VERFUEGBAR else "",
    "RESET":    Style.RESET_ALL            if FARBEN_VERFUEGBAR else "",
}

# Ausgabeverzeichnis für Dateien
AUSGABE_VERZEICHNIS = "reports"


class ReportGenerator:
    """
    Erstellt den Sicherheitsbericht im gewünschten Ausgabeformat.
    """

    def erstellen(self, bericht: Dict[str, Any], format: str = "text") -> None:
        """
        Dispatcher – leitet an das passende Format-Modul weiter.

        Parameter:
            bericht: Konsolidiertes Ergebnis-Dictionary aus audit.py
            format:  'text', 'json' oder 'html'
        """
        os.makedirs(AUSGABE_VERZEICHNIS, exist_ok=True)

        if format == "json":
            self._json_bericht(bericht)
        elif format == "html":
            self._html_bericht(bericht)
        else:
            self._text_bericht(bericht)

    # ------------------------------------------------------------------
    # Textausgabe
    # ------------------------------------------------------------------

    def _text_bericht(self, bericht: Dict[str, Any]) -> None:
        """Gibt den Bericht farbig im Terminal aus."""
        meta = bericht["meta"]
        ports = bericht["port_scan"]
        befunde = bericht["cis_benchmark"]

        # --- Offene Ports ---
        print(f"\n{'─'*60}")
        print(f"  OFFENE PORTS ({len(ports)} gefunden)")
        print(f"{'─'*60}")

        if ports:
            print(f"  {'PORT':<8} {'DIENST':<20} {'BANNER'}")
            print(f"  {'─'*6}  {'─'*18}  {'─'*28}")
            for p in ports:
                # Banner aus der Dienst-Analyse suchen
                banner = ""
                for d in bericht["dienste"]:
                    if d["port"] == p["port"]:
                        banner = d.get("banner", "")[:40]
                        break
                print(f"  {p['port']:<8} {p['dienst']:<20} {banner}")
        else:
            print("  Keine offenen Ports gefunden.")

        # --- CIS-Befunde ---
        print(f"\n{'─'*60}")
        print(f"  CIS-BENCHMARK-BEFUNDE ({len(befunde)} Befunde)")
        print(f"{'─'*60}")

        if befunde:
            for b in befunde:
                sg = b["schweregrad"]
                farbe = FARBE.get(sg, "")
                reset = FARBE["RESET"]
                print(f"\n  {farbe}[{sg}]{reset} {b['id']} – {b['titel']}")
                print(f"  Ursache:      {b['beschreibung']}")
                print(f"  Empfehlung:   {b['empfehlung']}")
        else:
            print(f"  {FARBE['OK']}Keine Befunde – alle geprüften CIS-Kontrollen bestanden.{FARBE['RESET']}")

        # --- Gesamtrisiko ---
        gesamtrisiko = self._gesamtrisiko(befunde)
        farbe = FARBE.get(gesamtrisiko, "")
        reset = FARBE["RESET"]
        print(f"\n{'─'*60}")
        print(f"  GESAMT-RISIKOSTUFE: {farbe}{gesamtrisiko}{reset}")
        print(f"{'─'*60}\n")

    # ------------------------------------------------------------------
    # JSON-Ausgabe
    # ------------------------------------------------------------------

    def _json_bericht(self, bericht: Dict[str, Any]) -> None:
        """
        Speichert den Bericht als strukturiertes JSON-Dokument.

        JSON eignet sich für die Integration in SIEM-Systeme (z.B. Splunk,
        Elastic Stack) oder automatisierte Weiterverarbeitung.
        """
        bericht["gesamt_risiko"] = self._gesamtrisiko(bericht["cis_benchmark"])

        zeitstempel = datetime.now().strftime("%Y%m%d_%H%M%S")
        dateiname = os.path.join(AUSGABE_VERZEICHNIS, f"audit_{zeitstempel}.json")

        with open(dateiname, "w", encoding="utf-8") as f:
            json.dump(bericht, f, ensure_ascii=False, indent=2)

        print(f"  JSON-Bericht gespeichert: {dateiname}")

    # ------------------------------------------------------------------
    # HTML-Ausgabe
    # ------------------------------------------------------------------

    def _html_bericht(self, bericht: Dict[str, Any]) -> None:
        """
        Erstellt einen interaktiven HTML-Bericht mit Bootstrap 5.

        Der Bericht enthält:
          - Zusammenfassungskarten (Ports, Befunde, Risikostufe)
          - Tabelle aller offenen Ports mit Dienst und Banner
          - Detaillierte CIS-Befundliste mit farblicher Hervorhebung
        """
        meta = bericht["meta"]
        ports = bericht["port_scan"]
        dienste = bericht["dienste"]
        befunde = bericht["cis_benchmark"]
        gesamtrisiko = self._gesamtrisiko(befunde)

        # Bootstrap-Farben für Schweregrade
        badge_farben = {
            "KRITISCH": "danger",
            "HOCH":     "warning text-dark",
            "MITTEL":   "info text-dark",
            "NIEDRIG":  "secondary",
            "BESTANDEN": "success",
        }

        # Port-Tabellen-Zeilen generieren
        port_zeilen = ""
        for p in ports:
            banner = ""
            for d in dienste:
                if d["port"] == p["port"]:
                    banner = d.get("banner", "")[:60]
                    break
            port_zeilen += (
                f"<tr><td>{p['port']}</td>"
                f"<td>{p['dienst']}</td>"
                f"<td><code>{banner}</code></td></tr>\n"
            )

        # CIS-Befund-Karten generieren
        befund_karten = ""
        for b in befunde:
            sg = b["schweregrad"]
            badge = badge_farben.get(sg, "secondary")
            befund_karten += f"""
            <div class="card mb-3 border-{'danger' if sg in ('KRITISCH', 'HOCH') else 'warning'}">
              <div class="card-header d-flex justify-content-between align-items-center">
                <strong>{b['id']} – {b['titel']}</strong>
                <span class="badge bg-{badge}">{sg}</span>
              </div>
              <div class="card-body">
                <p><strong>Betroffener Port:</strong> {b.get('betroffener_port', '–')}</p>
                <p><strong>Ursache:</strong> {b['beschreibung']}</p>
                <p class="mb-0"><strong>Empfehlung:</strong> {b['empfehlung']}</p>
              </div>
            </div>
            """

        risiko_badge = badge_farben.get(gesamtrisiko, "secondary")

        html = f"""<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sicherheits-Audit – {meta['ziel']}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-4">

  <h1 class="mb-1">Netzwerk-Sicherheits-Audit</h1>
  <p class="text-muted">Ziel: <code>{meta['ziel']}</code> &nbsp;|&nbsp; {meta['zeitstempel'][:19].replace('T', ' ')}</p>
  <hr>

  <!-- Zusammenfassung -->
  <div class="row g-3 mb-4">
    <div class="col-md-4">
      <div class="card text-center">
        <div class="card-body">
          <h2 class="card-title">{len(ports)}</h2>
          <p class="card-text text-muted">Offene Ports</p>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card text-center">
        <div class="card-body">
          <h2 class="card-title">{len(befunde)}</h2>
          <p class="card-text text-muted">CIS-Befunde</p>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card text-center">
        <div class="card-body">
          <h2 class="card-title">
            <span class="badge bg-{risiko_badge} fs-5">{gesamtrisiko}</span>
          </h2>
          <p class="card-text text-muted">Gesamt-Risikostufe</p>
        </div>
      </div>
    </div>
  </div>

  <!-- Offene Ports -->
  <h2 class="mt-4">Offene Ports</h2>
  <table class="table table-striped table-hover">
    <thead class="table-dark">
      <tr><th>Port</th><th>Dienst</th><th>Banner</th></tr>
    </thead>
    <tbody>
      {port_zeilen if port_zeilen else '<tr><td colspan="3" class="text-muted">Keine offenen Ports</td></tr>'}
    </tbody>
  </table>

  <!-- CIS-Befunde -->
  <h2 class="mt-4">CIS-Benchmark-Befunde</h2>
  {befund_karten if befund_karten else '<div class="alert alert-success">Alle geprüften CIS-Kontrollen bestanden.</div>'}

</div>
</body>
</html>"""

        zeitstempel = datetime.now().strftime("%Y%m%d_%H%M%S")
        dateiname = os.path.join(AUSGABE_VERZEICHNIS, f"audit_{zeitstempel}.html")

        with open(dateiname, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  HTML-Bericht gespeichert: {dateiname}")

    # ------------------------------------------------------------------
    # Hilfsmethoden
    # ------------------------------------------------------------------

    def _gesamtrisiko(self, befunde: list) -> str:
        """
        Berechnet das Gesamt-Risiko aus der Liste aller Befunde.

        Gibt den höchsten vorkommenden Schweregrad zurück.
        Keine Befunde → 'BESTANDEN'.
        """
        if not befunde:
            return "BESTANDEN"

        schweregrade = {b["schweregrad"] for b in befunde}

        if "KRITISCH" in schweregrade:
            return "KRITISCH"
        if "HOCH" in schweregrade:
            return "HOCH"
        if "MITTEL" in schweregrade:
            return "MITTEL"
        return "NIEDRIG"
