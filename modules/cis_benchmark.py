"""
cis_benchmark.py – CIS-Benchmark-Konformitätsprüfungen
=======================================================
Dieses Modul prüft die Scan-Ergebnisse gegen ausgewählte Kontrollen
des CIS (Center for Internet Security) Benchmarks – Level 1.

Was ist der CIS-Benchmark?
  Der CIS-Benchmark ist ein international anerkannter Standard für
  die Absicherung von IT-Systemen. Level 1 enthält grundlegende
  Sicherheitsmaßnahmen, die für alle Systeme empfohlen werden und
  den Betrieb nicht beeinträchtigen.

Implementierte Kontrollen:
  CIS-1.1  Unsichere Protokolle abschalten (Telnet, FTP, rsh, rlogin)
  CIS-1.2  NetBIOS/SMB nicht nach außen exponieren
  CIS-2.1  SSH auf Standard-Port 22 erhöht Angriffsfläche
  CIS-2.2  Veraltete SSH-Protokollversion
  CIS-3.1  Remote-Desktop/VNC ohne VPN erreichbar
  CIS-3.2  Datenbankports direkt erreichbar
  CIS-4.1  Unverschlüsseltes HTTP aktiv
  CIS-5.1  Unsichere In-Memory-Dienste erreichbar (Redis, Memcached)
  CIS-5.2  RPC-Dienste unnötig exponiert

Schweregrade:
  KRITISCH – Sofortiger Handlungsbedarf, aktives Angriffspotenzial
  HOCH     – Zeitnahe Behebung notwendig
  MITTEL   – Mittelfristig beheben, Risiko vorhanden
  NIEDRIG  – Best-Practice-Abweichung, geringes Risiko
"""

from typing import List, Dict, Any


# Ports unsicherer Legacy-Protokolle, die nicht offen sein sollten
UNSICHERE_PROTOKOLLE: Dict[int, str] = {
    21:  "FTP – Überträgt Daten und Passwörter im Klartext",
    23:  "Telnet – Gesamte Sitzung unverschlüsselt",
    69:  "TFTP – Kein Authentifizierungsmechanismus vorhanden",
    513: "rlogin – Veralteter Remote-Login ohne Verschlüsselung",
    514: "rsh – Remote Shell ohne Verschlüsselung oder Authentifizierung",
    517: "talk – Unverschlüsselter Nachrichtendienst",
    518: "ntalk – Unverschlüsselter Nachrichtendienst",
}

# Windows-Netzwerkdienste – außerhalb des internen LANs kritisch
SMB_PORTS: Dict[int, str] = {
    135: "MSRPC",
    139: "NetBIOS-SSN",
    445: "SMB",
}

# Remote-Zugriffs-Dienste – erhöhtes Risiko ohne VPN
REMOTE_ZUGANG_PORTS: Dict[int, str] = {
    3389: "RDP (Remote Desktop Protocol)",
    5900: "VNC",
    5901: "VNC Display 1",
    5902: "VNC Display 2",
}

# Datenbankdienste – sollten nicht direkt von außen erreichbar sein
DATENBANK_PORTS: Dict[int, str] = {
    1433:  "Microsoft SQL Server",
    1521:  "Oracle Database",
    3306:  "MySQL / MariaDB",
    5432:  "PostgreSQL",
    6379:  "Redis (oft ohne Authentifizierung)",
    11211: "Memcached (keine Authentifizierung)",
    27017: "MongoDB",
    27018: "MongoDB (Shard)",
    28017: "MongoDB HTTP Interface",
}


class CISBenchmark:
    """
    Prüft Scan-Ergebnisse gegen CIS-Benchmark Level 1.

    Jede Prüfmethode gibt eine Liste von Befunden zurück.
    Ein Befund enthält:
        - id:             CIS-Kontrollen-Nummer
        - schweregrad:    KRITISCH / HOCH / MITTEL / NIEDRIG
        - titel:          Kurzbeschreibung des Befunds
        - beschreibung:   Detaillierte Erläuterung
        - empfehlung:     Konkrete Maßnahme zur Behebung
        - betroffener_port: Betroffener Port (falls zutreffend)
    """

    def pruefen(
        self,
        scan_ergebnisse: List[Dict[str, Any]],
        dienst_ergebnisse: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Führt alle CIS-Prüfungen durch und gibt eine konsolidierte
        Befundliste zurück, sortiert nach Schweregrad.
        """
        offene_ports = {e["port"] for e in scan_ergebnisse}
        alle_befunde = []

        # Jede Prüfung aufrufen und Ergebnisse sammeln
        alle_befunde.extend(self._pruefe_unsichere_protokolle(offene_ports))
        alle_befunde.extend(self._pruefe_smb_netbios(offene_ports))
        alle_befunde.extend(self._pruefe_remote_zugang(offene_ports))
        alle_befunde.extend(self._pruefe_datenbank_ports(offene_ports))
        alle_befunde.extend(self._pruefe_http_ohne_tls(offene_ports))
        alle_befunde.extend(self._pruefe_ssh_konfiguration(offene_ports, dienst_ergebnisse))
        alle_befunde.extend(self._pruefe_rpc_exposition(offene_ports))

        # Sortierung: KRITISCH zuerst, dann HOCH, MITTEL, NIEDRIG
        reihenfolge = {"KRITISCH": 0, "HOCH": 1, "MITTEL": 2, "NIEDRIG": 3}
        return sorted(alle_befunde, key=lambda x: reihenfolge.get(x["schweregrad"], 99))

    def _pruefe_unsichere_protokolle(self, offene_ports: set) -> List[Dict]:
        """
        CIS-1.1 – Unsichere Legacy-Protokolle dürfen nicht offen sein.

        Telnet, FTP, rsh und rlogin übertragen Daten einschließlich
        Passwörter unverschlüsselt. Ein Angreifer im Netzwerk kann
        Zugangsdaten mit einfachen Mitteln abfangen (Packet Sniffing).
        """
        befunde = []
        for port, beschreibung in UNSICHERE_PROTOKOLLE.items():
            if port in offene_ports:
                befunde.append({
                    "id": "CIS-1.1",
                    "schweregrad": "KRITISCH",
                    "betroffener_port": port,
                    "titel": f"Unsicheres Protokoll offen: Port {port}",
                    "beschreibung": beschreibung,
                    "empfehlung": (
                        f"Dienst auf Port {port} deaktivieren. "
                        "Ersatz: SSH statt Telnet/rsh/rlogin, SFTP/SCP statt FTP."
                    ),
                })
        return befunde

    def _pruefe_smb_netbios(self, offene_ports: set) -> List[Dict]:
        """
        CIS-1.2 – SMB und NetBIOS nicht nach außen exponieren.

        SMB (Port 445) und NetBIOS (139) wurden bei kritischen Angriffen
        wie WannaCry und NotPetya ausgenutzt. Diese Dienste gehören
        ausschließlich ins interne LAN, nicht ins Internet.
        """
        befunde = []
        for port, dienst in SMB_PORTS.items():
            if port in offene_ports:
                befunde.append({
                    "id": "CIS-1.2",
                    "schweregrad": "KRITISCH",
                    "betroffener_port": port,
                    "titel": f"{dienst} von außen erreichbar (Port {port})",
                    "beschreibung": (
                        f"Port {port} ({dienst}) ist öffentlich erreichbar. "
                        "SMB/NetBIOS wurde bei WannaCry und NotPetya ausgenutzt."
                    ),
                    "empfehlung": (
                        "Firewall-Regel: Port 135, 139, 445 nur im internen Netz erlauben. "
                        "Kein Routing dieser Ports über das Internet-Gateway."
                    ),
                })
        return befunde

    def _pruefe_remote_zugang(self, offene_ports: set) -> List[Dict]:
        """
        CIS-3.1 – Remote-Desktop und VNC nur über VPN erreichbar.

        RDP (Port 3389) und VNC sind häufige Angriffsziele für
        Brute-Force-Attacken und ungepatchte Exploits (z.B. BlueKeep).
        Direkter Internetzugang erhöht das Risiko erheblich.
        """
        befunde = []
        for port, dienst in REMOTE_ZUGANG_PORTS.items():
            if port in offene_ports:
                befunde.append({
                    "id": "CIS-3.1",
                    "schweregrad": "HOCH",
                    "betroffener_port": port,
                    "titel": f"{dienst} direkt erreichbar (Port {port})",
                    "beschreibung": (
                        f"{dienst} ist ohne vorgelagerten VPN-Tunnel erreichbar. "
                        "Brute-Force und bekannte Exploits sind aktiv im Einsatz."
                    ),
                    "empfehlung": (
                        f"Port {port} in der Firewall sperren. "
                        "Zugriff ausschließlich über VPN (IPsec/WireGuard/OpenVPN) erlauben."
                    ),
                })
        return befunde

    def _pruefe_datenbank_ports(self, offene_ports: set) -> List[Dict]:
        """
        CIS-3.2 – Datenbankports nicht direkt aus dem Internet erreichbar.

        Datenbanken wie MySQL, PostgreSQL oder MongoDB sollten nie
        direkt ans Internet gebunden sein. Redis und Memcached haben
        standardmäßig keine Authentifizierung und sind besonders riskant.
        """
        befunde = []
        for port, dienst in DATENBANK_PORTS.items():
            if port in offene_ports:
                # Redis und Memcached: keine Auth → kritisch
                schweregrad = "KRITISCH" if port in (6379, 11211) else "HOCH"
                befunde.append({
                    "id": "CIS-3.2",
                    "schweregrad": schweregrad,
                    "betroffener_port": port,
                    "titel": f"Datenbankport erreichbar: {dienst} (Port {port})",
                    "beschreibung": (
                        f"{dienst} auf Port {port} ist direkt erreichbar. "
                        "Datenbanken dürfen nicht ohne vorgelagerte Sicherheitsschicht exponiert sein."
                    ),
                    "empfehlung": (
                        f"Datenbankport {port} in der Firewall blockieren. "
                        "Anwendungen sollen intern über localhost oder ein privates Netz zugreifen."
                    ),
                })
        return befunde

    def _pruefe_http_ohne_tls(self, offene_ports: set) -> List[Dict]:
        """
        CIS-4.1 – Unverschlüsseltes HTTP abschalten oder auf HTTPS umleiten.

        HTTP auf Port 80 überträgt Daten im Klartext. Auch wenn heute
        viele Seiten auf HTTPS umleiten, sollte Port 80 idealerweise
        nur für die Weiterleitung zu HTTPS offen sein.
        """
        befunde = []
        http_ports = {80, 8080, 8000}
        gefunden = offene_ports & http_ports

        for port in gefunden:
            befunde.append({
                "id": "CIS-4.1",
                "schweregrad": "NIEDRIG",
                "betroffener_port": port,
                "titel": f"HTTP ohne TLS aktiv (Port {port})",
                "beschreibung": (
                    f"Port {port} bietet HTTP ohne Verschlüsselung an. "
                    "Übertragene Daten (inkl. Session-Cookies) sind im Netzwerk lesbar."
                ),
                "empfehlung": (
                    "HTTP-zu-HTTPS-Weiterleitung einrichten (301 Redirect). "
                    "HSTS-Header setzen: Strict-Transport-Security: max-age=31536000"
                ),
            })
        return befunde

    def _pruefe_ssh_konfiguration(self, offene_ports: set, dienste: List[Dict]) -> List[Dict]:
        """
        CIS-2.1 / CIS-2.2 – SSH-Konfiguration prüfen.

        SSH auf dem Standard-Port 22 wird automatisch von Bots gescannt.
        Ein geänderter Port reduziert den Log-Lärm, ist aber kein
        Sicherheitsmerkmal (Security through Obscurity).
        Veraltete SSH-Versionen können bekannte Schwachstellen enthalten.
        """
        befunde = []
        if 22 not in offene_ports:
            return befunde

        # CIS-2.1: SSH auf Standard-Port
        befunde.append({
            "id": "CIS-2.1",
            "schweregrad": "MITTEL",
            "betroffener_port": 22,
            "titel": "SSH läuft auf Standard-Port 22",
            "beschreibung": (
                "Port 22 wird von automatisierten Bots dauerhaft auf "
                "Brute-Force-Angriffe und bekannte Exploits geprüft."
            ),
            "empfehlung": (
                "SSH auf einen nicht-standardmäßigen Port (z.B. 2222) verschieben. "
                "Zusätzlich: Fail2ban oder ähnliches Rate-Limiting einsetzen. "
                "Passwort-Authentifizierung deaktivieren, nur SSH-Keys verwenden."
            ),
        })

        # CIS-2.2: SSH-Banner auf Protokollversion prüfen
        for dienst in dienste:
            if dienst["port"] == 22 and "ssh-1" in dienst.get("banner", "").lower():
                befunde.append({
                    "id": "CIS-2.2",
                    "schweregrad": "KRITISCH",
                    "betroffener_port": 22,
                    "titel": "SSH-Protokoll Version 1 erkannt",
                    "beschreibung": (
                        "SSH-Protokollversion 1 hat bekannte kryptografische Schwächen "
                        "und gilt seit RFC 4253 (2006) als veraltet."
                    ),
                    "empfehlung": (
                        "In /etc/ssh/sshd_config eintragen: Protocol 2  "
                        "SSH-Dienst neu starten: systemctl restart sshd"
                    ),
                })

        return befunde

    def _pruefe_rpc_exposition(self, offene_ports: set) -> List[Dict]:
        """
        CIS-5.2 – RPC-Dienste nicht nach außen exponieren.

        RPC (Remote Procedure Call, Port 111) wird für NFS, NIS und andere
        Legacy-Dienste genutzt. Über den RPC-Portmapper können Angreifer
        weitere aktive Dienste und ihre Ports abfragen.
        """
        befunde = []
        rpc_ports = {111: "RPC-Portmapper", 2049: "NFS"}

        for port, dienst in rpc_ports.items():
            if port in offene_ports:
                befunde.append({
                    "id": "CIS-5.2",
                    "schweregrad": "HOCH",
                    "betroffener_port": port,
                    "titel": f"{dienst} erreichbar (Port {port})",
                    "beschreibung": (
                        f"{dienst} auf Port {port} erlaubt die Enumeration weiterer Dienste "
                        "und ist typischerweise nur im internen Netz erforderlich."
                    ),
                    "empfehlung": (
                        f"Firewall-Regel: Port {port} nach außen blockieren. "
                        "NFS-Exporte auf interne IP-Bereiche beschränken."
                    ),
                })
        return befunde
