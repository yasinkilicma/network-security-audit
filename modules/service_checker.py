"""
service_checker.py – Dienst-Analyse und Banner-Grabbing
========================================================
Dieses Modul analysiert die auf den offenen Ports laufenden Dienste.
Mittels Banner-Grabbing wird versucht, die genaue Software-Version
zu ermitteln. Anschließend werden bekannte Schwachstellen-Muster
geprüft.

Banner-Grabbing:
  Nach dem Verbindungsaufbau warten manche Dienste (z.B. FTP, SMTP, SSH)
  automatisch mit einem Willkommensbanner. Dieses enthält oft den
  Software-Namen und die Version – wertvolle Informationen für den
  Angreifer und damit ein Sicherheitsrisiko.

HTTP-Header-Analyse:
  Für HTTP/HTTPS-Ports wird ein GET-Request gesendet und der
  Server-Header ausgewertet. Ein sichtbarer Server-Header
  (z.B. "Apache/2.4.51") gilt als informativer Datenleck.
"""

import socket
from typing import List, Dict, Any


# Minimale HTTP-Anfrage für Banner-Grabbing auf Web-Servern
HTTP_PROBE = b"GET / HTTP/1.0\r\nHost: target\r\n\r\n"

# Ports, bei denen ein HTTP-Probe sinnvoll ist
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888}


class ServiceChecker:
    """
    Analysiert Dienste auf offenen Ports via Banner-Grabbing.

    Für jeden offenen Port wird versucht:
      1. TCP-Verbindung aufbauen
      2. Auf spontanes Banner warten (FTP, SSH, SMTP etc.)
      3. Bei HTTP-Ports: GET-Request senden und Server-Header auslesen
      4. Banner auf bekannte Schwachstellenmuster prüfen

    Parameter:
        timeout (float): Wartezeit auf Banner in Sekunden.
    """

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def pruefen(self, scan_ergebnisse: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analysiert alle offenen Ports aus dem Port-Scan.

        Parameter:
            scan_ergebnisse: Ausgabe von PortScanner.scan()

        Rückgabe:
            Liste von Dienst-Einträgen, erweitert um 'banner' und 'befunde'.
        """
        dienste = []

        for eintrag in scan_ergebnisse:
            host = eintrag["host"]
            port = eintrag["port"]

            # Banner ermitteln
            banner = self._banner_grabbing(host, port)

            # Dienst-spezifische Sicherheitsprüfungen
            befunde = self._sicherheit_pruefen(port, banner)

            dienste.append({
                "host":    host,
                "port":    port,
                "dienst":  eintrag["dienst"],
                "banner":  banner,
                "befunde": befunde,
            })

        return dienste

    def _banner_grabbing(self, host: str, port: int) -> str:
        """
        Versucht, das Dienst-Banner eines Ports zu lesen.

        Bei HTTP-Ports wird ein GET-Request gesendet, um den
        Server-Header zu erhalten. Bei anderen Ports wird auf
        ein spontanes Begrüßungs-Banner gewartet.

        Rückgabe:
            Banner-Text oder leerer String bei Misserfolg.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((host, port))

                if port in HTTP_PORTS:
                    # HTTP-Probe senden und Antwort-Header lesen
                    sock.sendall(HTTP_PROBE)

                # Ersten Datenpakete empfangen (max. 1024 Bytes)
                daten = sock.recv(1024)
                banner = daten.decode("utf-8", errors="ignore").strip()

                # Nur die erste Zeile des Banners zurückgeben
                return banner.splitlines()[0] if banner else ""

        except (socket.timeout, socket.error, OSError):
            return ""

    def _sicherheit_pruefen(self, port: int, banner: str) -> List[Dict[str, str]]:
        """
        Prüft das Banner auf bekannte Sicherheitsprobleme.

        Analysiert werden:
          - Veraltete SSH-Protokollversionen (SSHv1)
          - Bekannte verwundbare Software-Versionen
          - Sichtbare Server-Informationen (informativer Datenleck)
          - Unverschlüsselte Übertragungskanäle

        Rückgabe:
            Liste von Befund-Dictionaries mit 'typ' und 'beschreibung'.
        """
        befunde = []
        banner_lower = banner.lower()

        # SSH-Protokollversion 1 ist seit 2001 als unsicher bekannt
        if port == 22 and "ssh-1" in banner_lower:
            befunde.append({
                "typ": "KRITISCH",
                "beschreibung": "SSH-Protokollversion 1 erkannt – sofort auf SSHv2 wechseln",
            })

        # HTTP Server-Header offenbart Software und Version
        if port in HTTP_PORTS and ("apache" in banner_lower or "nginx" in banner_lower or "iis" in banner_lower):
            befunde.append({
                "typ": "NIEDRIG",
                "beschreibung": f"Server-Version sichtbar im HTTP-Header: '{banner[:80]}'",
            })

        # Veraltete Apache-Version (Beispiel-Prüfung)
        if "apache/2.2" in banner_lower:
            befunde.append({
                "typ": "HOCH",
                "beschreibung": "Veraltete Apache-Version 2.2 erkannt – Ende des Support-Zeitraums",
            })

        # OpenSSH-Version auslesen und prüfen
        if "openssh" in banner_lower:
            try:
                # Format: SSH-2.0-OpenSSH_8.4
                version_str = banner.split("OpenSSH_")[1].split()[0]
                haupt, neben = version_str.split(".")[:2]
                if int(haupt) < 8:
                    befunde.append({
                        "typ": "MITTEL",
                        "beschreibung": f"OpenSSH-Version {version_str} – Update auf Version 8.x oder höher empfohlen",
                    })
            except (IndexError, ValueError):
                pass

        return befunde
