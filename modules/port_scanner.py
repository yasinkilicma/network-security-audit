"""
port_scanner.py – TCP-Port-Scanner
===================================
Dieses Modul führt einen TCP-Connect-Scan durch. Für jeden angegebenen
Port wird versucht, eine vollständige TCP-Verbindung aufzubauen.
Gibt der Zielhost einen SYN-ACK zurück, gilt der Port als offen.

Technischer Hintergrund:
  Der TCP-Connect-Scan (auch Full-Open-Scan) ist die einfachste Form
  des Port-Scannings. Im Gegensatz zum SYN-Scan (Half-Open) wird die
  Verbindung vollständig aufgebaut. Dies erfordert keine Root-Rechte,
  hinterlässt jedoch vollständige Einträge in Server-Logdateien.

Parallele Verarbeitung:
  Um den Scan zu beschleunigen, werden die Ports mithilfe eines
  ThreadPoolExecutors parallel geprüft. Die Anzahl der Threads ist
  über den Parameter --threads einstellbar.
"""

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any


# Zuordnung bekannter Ports zu ihren Standard-Diensten.
# Wird verwendet, wenn kein Banner ermittelt werden kann.
BEKANNTE_PORTS: Dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    111:   "RPC",
    135:   "MSRPC",
    139:   "NetBIOS-SSN",
    143:   "IMAP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    513:   "rlogin",
    514:   "rsh",
    515:   "LPD",
    587:   "SMTP-Submission",
    636:   "LDAPS",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "Oracle-DB",
    2049:  "NFS",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    5901:  "VNC-1",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    11211: "Memcached",
    27017: "MongoDB",
}


class PortScanner:
    """
    Führt einen parallelen TCP-Connect-Scan auf einem oder mehreren Hosts durch.

    Parameter:
        timeout (float): Wartezeit in Sekunden pro Verbindungsversuch.
        threads (int):   Maximale Anzahl gleichzeitiger Scan-Threads.
    """

    def __init__(self, timeout: float = 1.0, threads: int = 100):
        self.timeout = timeout
        self.threads = threads

    def scan(self, ziel: str, ports: str) -> List[Dict[str, Any]]:
        """
        Startet den Scan für das angegebene Ziel und den Port-Bereich.

        Parameter:
            ziel (str):  IP-Adresse oder CIDR-Netzwerk.
            ports (str): Port-Bereich ("1-1024"), Liste ("22,80,443") oder beides.

        Rückgabe:
            Liste von Dictionaries. Jeder Eintrag beschreibt einen offenen Port:
            {
                "host":    "192.168.1.1",
                "port":    22,
                "dienst": "SSH"
            }
        """
        hosts = self._hosts_ermitteln(ziel)
        port_liste = self._ports_parsen(ports)

        offene_ports = []

        # Für jeden Host den kompletten Port-Scan durchführen
        for host in hosts:
            print(f"     Scanne {host} ({len(port_liste)} Ports)...")
            ergebnisse = self._host_scannen(host, port_liste)
            offene_ports.extend(ergebnisse)

        # Ergebnisse nach Port-Nummer sortieren
        return sorted(offene_ports, key=lambda x: x["port"])

    def _host_scannen(self, host: str, ports: List[int]) -> List[Dict[str, Any]]:
        """
        Scannt alle Ports eines einzelnen Hosts parallel.

        Nutzt ThreadPoolExecutor: Jeder Thread prüft einen Port.
        Abgeschlossene Futures werden via as_completed() gesammelt.
        """
        offene_ports = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Alle Port-Prüfungen gleichzeitig starten
            futures = {
                executor.submit(self._port_pruefen, host, port): port
                for port in ports
            }

            for future in as_completed(futures):
                ergebnis = future.result()
                if ergebnis:  # None bedeutet: Port geschlossen
                    offene_ports.append(ergebnis)

        return offene_ports

    def _port_pruefen(self, host: str, port: int) -> Dict[str, Any] | None:
        """
        Versucht, eine TCP-Verbindung zu host:port aufzubauen.

        Rückgabe:
            Dictionary mit Host, Port und Dienst-Name – oder None wenn geschlossen.
        """
        try:
            # AF_INET = IPv4, SOCK_STREAM = TCP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                # connect_ex gibt 0 zurück wenn erfolgreich, sonst Fehlercode
                if sock.connect_ex((host, port)) == 0:
                    return {
                        "host": host,
                        "port": port,
                        "dienst": BEKANNTE_PORTS.get(port, "unbekannt"),
                    }
        except (socket.error, OSError):
            # Verbindungsfehler bedeuten: Port nicht erreichbar
            pass
        return None

    def _hosts_ermitteln(self, ziel: str) -> List[str]:
        """
        Wandelt eine IP-Adresse oder ein CIDR-Netzwerk in eine Host-Liste um.

        Beispiele:
            "192.168.1.1"      -> ["192.168.1.1"]
            "192.168.1.0/24"   -> ["192.168.1.1", ..., "192.168.1.254"]
        """
        try:
            netz = ipaddress.ip_network(ziel, strict=False)
            # Bei /32 gibt hosts() eine leere Liste zurück – daher Fallback
            hosts = [str(ip) for ip in netz.hosts()]
            return hosts if hosts else [str(netz.network_address)]
        except ValueError:
            # Kein gültiges CIDR – als einzelne IP behandeln
            return [ziel]

    def _ports_parsen(self, ports_str: str) -> List[int]:
        """
        Wandelt einen Port-String in eine sortierte Liste von Integers um.

        Unterstützte Formate:
            "22"           -> [22]
            "22,80,443"    -> [22, 80, 443]
            "1-1024"       -> [1, 2, ..., 1024]
            "22,80,100-200"-> [22, 80, 100, 101, ..., 200]
        """
        port_set = set()

        for teil in ports_str.split(","):
            teil = teil.strip()
            if "-" in teil:
                # Bereich: z.B. "1-1024"
                start, ende = teil.split("-", 1)
                port_set.update(range(int(start), int(ende) + 1))
            else:
                # Einzelner Port
                port_set.add(int(teil))

        return sorted(port_set)
