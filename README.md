# Netzwerk-Sicherheits-Audit-Tool

Ein automatisiertes Python-Tool zur Sicherheitsprüfung von Netzwerkgeräten und -diensten.
Es kombiniert Port-Scanning, Dienst-Analyse und CIS-Benchmark-Konformitätsprüfungen
in einem einheitlichen, übersichtlichen Bericht.

---

## Funktionsumfang

| Modul | Beschreibung |
|---|---|
| **Port-Scanner** | TCP-Connect-Scan mit einstellbarem Port-Bereich und parallelen Threads |
| **Dienst-Prüfer** | Banner-Grabbing, SSH-Version-Analyse, HTTP-Header-Auswertung |
| **CIS-Benchmark** | Prüfung gegen CIS-Sicherheitsrichtlinien (Level 1) |
| **Berichterstattung** | Ausgabe als Text (Terminal), JSON oder HTML |

---

## Voraussetzungen

- Python 3.8 oder höher
- Abhängigkeiten aus `requirements.txt`

```bash
pip install -r requirements.txt
```

---

## Installation

```bash
git clone https://github.com/yasinkilicma/network-security-audit.git
cd network-security-audit
pip install -r requirements.txt
```

---

## Verwendung

```bash
# Einfacher Scan eines einzelnen Hosts
python audit.py --target 192.168.1.1

# Scan mit erweitertem Port-Bereich
python audit.py --target 192.168.1.1 --ports 1-65535

# Scan eines ganzen Subnetzwerks
python audit.py --target 192.168.1.0/24

# Ausgabe als HTML-Bericht
python audit.py --target 192.168.1.1 --output html

# Ausgabe als maschinenlesbares JSON
python audit.py --target 192.168.1.1 --output json

# Spezifische Ports prüfen
python audit.py --target 192.168.1.1 --ports 22,80,443,3389
```

### Alle Parameter

```
--target  / -t   Ziel-IP oder CIDR-Netzwerk      (Pflichtfeld)
--ports   / -p   Port-Bereich oder Liste          (Standard: 1-1024)
--output  / -o   Ausgabeformat: text, json, html  (Standard: text)
--timeout        Verbindungs-Timeout in Sek.      (Standard: 1.0)
--threads        Anzahl paralleler Threads        (Standard: 100)
```

---

## Beispielausgabe (Terminal)

```
============================================================
  NETZWERK-SICHERHEITS-AUDIT
  Ziel: 192.168.1.1
  Zeitstempel: 31.05.2026 14:22:10
============================================================

[1/3] Starte Port-Scanning...
[2/3] Analysiere erkannte Dienste...
[3/3] Führe CIS-Benchmark-Prüfungen durch...

--- OFFENE PORTS ---
  PORT   DIENST    BANNER
  22     SSH       SSH-2.0-OpenSSH_8.4
  80     HTTP      Apache/2.4.51
  3306   MySQL     -

--- CIS-BENCHMARK-BEFUNDE ---
  [KRITISCH] CIS-1.1 – Unsicheres Protokoll: Telnet (Port 23) offen
  [HOCH]     CIS-3.2 – Datenbankport MySQL (3306) von außen erreichbar
  [MITTEL]   CIS-2.1 – SSH läuft auf Standard-Port 22
  [NIEDRIG]  CIS-4.1 – HTTP ohne TLS auf Port 80 aktiv

Gesamt-Risikostufe: HOCH
```

---

## CIS-Benchmark-Prüfungen

Das Tool prüft folgende CIS-Kontrollen (Center for Internet Security):

| ID | Kontrolle | Schweregrad |
|---|---|---|
| CIS-1.1 | Unsichere Protokolle offen (Telnet, FTP, rsh, rlogin) | KRITISCH |
| CIS-1.2 | Standard-Anmeldedienste (rexec, rlogin) erreichbar | KRITISCH |
| CIS-2.1 | SSH auf Standard-Port 22 | MITTEL |
| CIS-2.2 | Veraltete SSH-Version erkannt | HOCH |
| CIS-3.1 | RDP/VNC ohne Verschlüsselung erreichbar | HOCH |
| CIS-3.2 | Datenbankports von außen erreichbar | HOCH |
| CIS-4.1 | HTTP ohne TLS aktiv | NIEDRIG |
| CIS-4.2 | SMB/NetBIOS nach außen offen | KRITISCH |
| CIS-5.1 | Redis/Memcached ohne Authentifizierung | KRITISCH |

---

## Projektstruktur

```
network-security-audit/
├── audit.py                   # Hauptskript / Einstiegspunkt
├── requirements.txt
├── config/
│   └── targets.example.yaml   # Beispielkonfiguration
├── modules/
│   ├── port_scanner.py        # TCP-Port-Scanning
│   ├── service_checker.py     # Dienst-Analyse & Banner-Grabbing
│   ├── cis_benchmark.py       # CIS-Benchmark-Prüfungen
│   └── report_generator.py    # Berichterstattung (Text/JSON/HTML)
└── reports/                   # Generierte Berichte
```

---

## Sicherheitshinweis

> Dieses Tool darf **ausschließlich** auf Systemen verwendet werden,
> für die eine ausdrückliche Genehmigung vorliegt.
> Der Einsatz ohne Erlaubnis verstößt gegen § 202c StGB (Hackerparagraph).

---

## Zertifizierungsbezug

Dieses Projekt demonstriert praktische Kenntnisse aus:
- **CompTIA Network+** – Netzwerk-Scanning und Protokollanalyse
- **CompTIA Security+** – Schwachstellenanalyse und Sicherheitskontrollen
- **CompTIA CySA+** – Bedrohungserkennung und CIS-Benchmark-Konformität
