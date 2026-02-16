# PCAP Anonymizer

Ein kleines CLI-Tool zum Anonymisieren von Netzwerk-Mitschnitten (`.pcap` / `.pcapng`) mit [Scapy](https://scapy.net/).

## Funktionen

- Konsistente Ersetzung von:
  - IPv4 -> `10.x.x.x`
  - IPv6 -> `fd00::x`
  - MAC -> `02:00:00:xx:xx:xx`
  - DNS-Namen -> `host-N.anon.local`
- Erhält Broadcast-/Multicast-Adressen (z. B. `ff:ff:ff:ff:ff:ff`, `255.255.255.255`, IPv4-Multicast `224.0.0.0/4`, IPv6-Multicast `ff00::/8`)
- Unterstützt Ethernet, ARP, IP, IPv6, TCP, UDP und DNS (Queries + A/AAAA/CNAME/PTR/NS Records)
- Checksummen/Längenfelder werden von Scapy neu berechnet
- Optionale Mapping-Datei zum Wiederverwenden derselben Zuordnungen
- Optionaler `--seed` für reproduzierbare, aber pseudorandomisierte Mappings

## Quick Start

```bash
pip install scapy
python pcap_anonymizer.py input.pcap -o output_anon.pcap --seed 42
python pcap_anonymizer.py input2.pcap --map-file mapping.json -o input2_anon.pcap
```

## Voraussetzungen

- Python 3.10+
- `scapy`

Installation:

```bash
pip install scapy
```

## Nutzung

```bash
python pcap_anonymizer.py input.pcap -o output.pcap
```

Mit Mapping-Datei:

```bash
python pcap_anonymizer.py input.pcap -o output.pcap --map-file mapping.json
```

Mit Seed (reproduzierbar):

```bash
python pcap_anonymizer.py input.pcap -o output.pcap --seed 42
```

DNS-Anonymisierung deaktivieren:

```bash
python pcap_anonymizer.py input.pcap -o output.pcap --no-dns
```

## CLI-Optionen

- `input` Eingabedatei (`.pcap` oder `.pcapng`)
- `-o, --output` Ausgabedatei (Standard: `<input>_anon.pcap`)
- `--map-file` JSON-Datei zum Laden/Speichern von Mappings
- `--seed` Integer-Seed für reproduzierbare Mappings
- `--no-dns` DNS-Namen nicht anonymisieren

## Hinweise

- Das Tool anonymisiert Header-/Protokollfelder, nicht beliebige Nutzdaten in `Raw`-Payloads.
- Für wiederholte Läufe über mehrere Captures empfiehlt sich dieselbe `--map-file`.
- Bitte Ergebnis-PCAPs stichprobenartig prüfen, bevor du sie weitergibst.

## Lizenz

Derzeit keine Lizenz angegeben.
