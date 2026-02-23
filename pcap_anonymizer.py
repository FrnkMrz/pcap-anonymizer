#!/usr/bin/env python3
"""PCAP Anonymizer — consistently replace IPs, MACs, and DNS hostnames in packet captures."""

import argparse
import ipaddress
import json
import random
import sys
from collections import OrderedDict
from pathlib import Path

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    IP,
    TCP,
    UDP,
    Ether,
    IPv6,
    rdpcap,
    wrpcap,
)


# Addresses that should never be anonymized
RESERVED_MACS = {
    "ff:ff:ff:ff:ff:ff",
    "00:00:00:00:00:00",
}

RESERVED_IPS = {
    "0.0.0.0",
    "255.255.255.255",
    "127.0.0.1",
    "::1",
    "::",
}

MULTICAST_MAC_PREFIXES = ("01:00:5e", "33:33:")


def is_reserved_mac(mac: str) -> bool:
    """Return True if the MAC address should not be anonymized (broadcast, zero, or multicast)."""
    mac = mac.lower()
    if mac in RESERVED_MACS:
        return True
    return any(mac.startswith(p) for p in MULTICAST_MAC_PREFIXES)


def is_reserved_ip(ip: str) -> bool:
    """Return True if the IP address should not be anonymized (special/reserved/multicast)."""
    if ip in RESERVED_IPS:
        return True
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return parsed.is_multicast


class Anonymizer:
    @staticmethod
    def _next_unique(rng: random.Random, used: set[int], upper_bound: int) -> int:
        """Draw a random integer in [1, upper_bound) that hasn't been used yet."""
        while True:
            value = rng.randrange(1, upper_bound)
            if value not in used:
                used.add(value)
                return value

    @staticmethod
    def _parse_ip4_id(mapped: str):
        """Extract the 24-bit numeric ID encoded in a mapped 10.x.y.z address, or None."""
        parts = mapped.split(".")
        if len(parts) != 4 or parts[0] != "10":
            return None
        try:
            b1 = int(parts[1])
            b2 = int(parts[2])
            b3 = int(parts[3])
        except ValueError:
            return None
        if not all(0 <= b <= 255 for b in (b1, b2, b3)):
            return None
        return (b1 << 16) | (b2 << 8) | b3

    @staticmethod
    def _parse_ip6_id(mapped: str):
        """Extract the numeric ID encoded in a mapped fd00::<hex> address, or None."""
        prefix = "fd00::"
        if not mapped.lower().startswith(prefix):
            return None
        suffix = mapped[len(prefix):]
        try:
            value = int(suffix, 16)
        except ValueError:
            return None
        return value if value > 0 else None

    @staticmethod
    def _parse_mac_id(mapped: str):
        """Extract the 24-bit numeric ID encoded in a mapped 02:00:00:xx:xx:xx MAC, or None."""
        parts = mapped.lower().split(":")
        if len(parts) != 6 or parts[:3] != ["02", "00", "00"]:
            return None
        try:
            b1 = int(parts[3], 16)
            b2 = int(parts[4], 16)
            b3 = int(parts[5], 16)
        except ValueError:
            return None
        return (b1 << 16) | (b2 << 8) | b3

    @staticmethod
    def _parse_dns_id(mapped: str):
        """Extract the numeric ID encoded in a mapped host-<n>.anon.local name, or None."""
        prefix = "host-"
        suffix = ".anon.local"
        if not mapped.startswith(prefix) or not mapped.endswith(suffix):
            return None
        num = mapped[len(prefix):-len(suffix)]
        if not num.isdigit():
            return None
        value = int(num)
        return value if value > 0 else None

    def __init__(self, seed=None):
        # Optional seed makes anonymization reproducible across runs
        self.rng = random.Random(seed)
        # Ordered dicts preserve insertion order for deterministic JSON export
        self.ip4_map: OrderedDict[str, str] = OrderedDict()
        self.ip6_map: OrderedDict[str, str] = OrderedDict()
        self.mac_map: OrderedDict[str, str] = OrderedDict()
        self.dns_map: OrderedDict[str, str] = OrderedDict()
        # Track already-assigned IDs to guarantee uniqueness of mapped values
        self._used_ip4_ids: set[int] = set()
        self._used_ip6_ids: set[int] = set()
        self._used_mac_ids: set[int] = set()
        self._used_dns_ids: set[int] = set()

    def map_ip4(self, addr: str) -> str:
        """Return a consistent anonymized IPv4 address in the 10.0.0.0/8 range."""
        if is_reserved_ip(addr):
            return addr
        if addr not in self.ip4_map:
            n = self._next_unique(self.rng, self._used_ip4_ids, 1 << 24)
            b1 = (n >> 16) & 0xFF
            b2 = (n >> 8) & 0xFF
            b3 = n & 0xFF
            self.ip4_map[addr] = f"10.{b1}.{b2}.{b3}"
        return self.ip4_map[addr]

    def map_ip6(self, addr: str) -> str:
        """Return a consistent anonymized IPv6 address in the fd00::/8 ULA range."""
        if is_reserved_ip(addr):
            return addr
        key = addr.lower()
        if key not in self.ip6_map:
            n = self._next_unique(self.rng, self._used_ip6_ids, 1 << 64)
            self.ip6_map[key] = f"fd00::{n:x}"
        return self.ip6_map[key]

    def map_mac(self, addr: str) -> str:
        """Return a consistent anonymized MAC address using the locally-administered 02:00:00: prefix."""
        key = addr.lower()
        if is_reserved_mac(key):
            return addr
        if key not in self.mac_map:
            n = self._next_unique(self.rng, self._used_mac_ids, 1 << 24)
            b1 = (n >> 16) & 0xFF
            b2 = (n >> 8) & 0xFF
            b3 = n & 0xFF
            self.mac_map[key] = f"02:00:00:{b1:02x}:{b2:02x}:{b3:02x}"
        return self.mac_map[key]

    def map_dns(self, name: str) -> str:
        """Return a consistent anonymized DNS name of the form host-<n>.anon.local.

        The trailing dot (FQDN indicator) is preserved when present.
        """
        key = name.lower().rstrip(".")
        if not key:
            return name
        if key not in self.dns_map:
            n = self._next_unique(self.rng, self._used_dns_ids, 1 << 31)
            self.dns_map[key] = f"host-{n}.anon.local"
        mapped = self.dns_map[key]
        # Preserve the trailing dot so FQDN-formatted names stay valid
        if name.endswith("."):
            mapped += "."
        return mapped

    def export_mapping(self) -> dict:
        """Return the full address mapping as a plain dict suitable for JSON serialization."""
        return {
            "ipv4": dict(self.ip4_map),
            "ipv6": dict(self.ip6_map),
            "mac": dict(self.mac_map),
            "dns": dict(self.dns_map),
        }

    def load_mapping(self, data: dict):
        """Populate the anonymizer from a previously exported mapping dict.

        Already-assigned IDs are re-registered so new addresses never collide
        with values loaded from a prior run.
        """
        if "ipv4" in data:
            self.ip4_map.update(data["ipv4"])
            for mapped in self.ip4_map.values():
                value = self._parse_ip4_id(mapped)
                if value is not None:
                    self._used_ip4_ids.add(value)
        if "ipv6" in data:
            self.ip6_map.update(data["ipv6"])
            for mapped in self.ip6_map.values():
                value = self._parse_ip6_id(mapped)
                if value is not None:
                    self._used_ip6_ids.add(value)
        if "mac" in data:
            self.mac_map.update(data["mac"])
            for mapped in self.mac_map.values():
                value = self._parse_mac_id(mapped)
                if value is not None:
                    self._used_mac_ids.add(value)
        if "dns" in data:
            self.dns_map.update(data["dns"])
            for mapped in self.dns_map.values():
                value = self._parse_dns_id(mapped)
                if value is not None:
                    self._used_dns_ids.add(value)


def anonymize_packet(pkt, anon: Anonymizer, do_dns: bool = True):
    """Anonymize a single packet in-place and return it."""
    # Ethernet layer
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        eth.src = anon.map_mac(eth.src)
        eth.dst = anon.map_mac(eth.dst)

    # ARP layer
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        arp.hwsrc = anon.map_mac(arp.hwsrc)
        arp.hwdst = anon.map_mac(arp.hwdst)
        arp.psrc = anon.map_ip4(arp.psrc)
        arp.pdst = anon.map_ip4(arp.pdst)

    # IPv4 layer
    if pkt.haslayer(IP):
        ip = pkt[IP]
        ip.src = anon.map_ip4(ip.src)
        ip.dst = anon.map_ip4(ip.dst)
        # Delete checksum so scapy recomputes
        del ip.chksum
        del ip.len
        if pkt.haslayer(TCP):
            del pkt[TCP].chksum
        if pkt.haslayer(UDP):
            del pkt[UDP].chksum
            del pkt[UDP].len

    # IPv6 layer
    if pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        ip6.src = anon.map_ip6(ip6.src)
        ip6.dst = anon.map_ip6(ip6.dst)
        del ip6.plen
        if pkt.haslayer(TCP):
            del pkt[TCP].chksum
        if pkt.haslayer(UDP):
            del pkt[UDP].chksum
            del pkt[UDP].len

    # DNS layer — scapy's .qd/.an/.ns/.ar accessors return copies, so we
    # must rebuild the DNS layer with anonymized fields.
    if do_dns and pkt.haslayer(DNS):
        _anonymize_dns_layer(pkt, anon)

    return pkt


def _dns_name_to_str(name) -> str:
    """Decode a DNS name field to a plain string regardless of whether scapy returned bytes or str."""
    if isinstance(name, bytes):
        return name.decode("utf-8", errors="replace")
    return str(name)


def _anonymize_dns_layer(pkt, anon: Anonymizer):
    """Rebuild the DNS layer with anonymized names.

    Scapy 2.7+ returns list-like objects for qd/an/ns/ar sections,
    so we iterate and rebuild each record.
    """
    dns = pkt[DNS]

    # Anonymize question records
    qd_list = dns.qd
    if qd_list:
        new_qds = []
        for qd in (qd_list if hasattr(qd_list, "__iter__") else [qd_list]):
            orig = _dns_name_to_str(qd.qname)
            new_qds.append(DNSQR(
                qname=anon.map_dns(orig).encode(),
                qtype=qd.qtype,
                qclass=qd.qclass,
            ))
        dns.qd = new_qds

    # Anonymize RR sections (answer, authority, additional)
    for section in ("an", "ns", "ar"):
        rr_list = getattr(dns, section, None)
        if not rr_list:
            continue
        new_rrs = []
        for rr in (rr_list if hasattr(rr_list, "__iter__") else [rr_list]):
            if not isinstance(rr, DNSRR):
                new_rrs.append(rr)
                continue
            orig_name = _dns_name_to_str(rr.rrname)
            kwargs = {
                "rrname": anon.map_dns(orig_name).encode(),
                "type": rr.type,
                "rclass": rr.rclass,
                "ttl": rr.ttl,
            }
            rtype = rr.type
            if rtype == 1:  # A record — anonymize the IPv4 address in rdata
                kwargs["rdata"] = anon.map_ip4(rr.rdata)
            elif rtype == 28:  # AAAA record — anonymize the IPv6 address in rdata
                kwargs["rdata"] = anon.map_ip6(rr.rdata)
            elif rtype in (5, 12, 2):  # CNAME / PTR / NS — anonymize the target name
                orig_rdata = _dns_name_to_str(rr.rdata)
                kwargs["rdata"] = anon.map_dns(orig_rdata).encode()
            else:
                # All other record types (MX, TXT, SOA, …) are left untouched
                kwargs["rdata"] = rr.rdata
            new_rrs.append(DNSRR(**kwargs))
        setattr(dns, section, new_rrs)


def main():
    parser = argparse.ArgumentParser(
        description="Anonymize IP addresses, MAC addresses, and DNS hostnames in pcap files."
    )
    parser.add_argument("input", help="Input pcap/pcapng file")
    parser.add_argument("-o", "--output", help="Output pcap file (default: <input>_anon.pcap)")
    parser.add_argument("--map-file", help="JSON file to save/load address mappings")
    parser.add_argument("--seed", type=int, help="Seed for reproducible anonymization")
    parser.add_argument("--no-dns", action="store_true", help="Skip DNS hostname anonymization")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: input file '{input_path}' not found", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.with_stem(input_path.stem + "_anon").with_suffix(".pcap")

    anon = Anonymizer(seed=args.seed)

    # Load existing mapping if provided and file exists
    if args.map_file and Path(args.map_file).exists():
        with open(args.map_file) as f:
            anon.load_mapping(json.load(f))
        print(f"Loaded existing mappings from {args.map_file}")

    # Read packets
    print(f"Reading {input_path}...")
    packets = rdpcap(str(input_path))
    print(f"Read {len(packets)} packets")

    # Anonymize
    print("Anonymizing...")
    do_dns = not args.no_dns
    anon_packets = []
    for pkt in packets:
        anon_packets.append(anonymize_packet(pkt, anon, do_dns=do_dns))

    # Write output
    print(f"Writing {output_path}...")
    wrpcap(str(output_path), anon_packets)

    # Export mapping
    if args.map_file:
        with open(args.map_file, "w") as f:
            json.dump(anon.export_mapping(), f, indent=2)
        print(f"Mapping saved to {args.map_file}")

    mapping = anon.export_mapping()
    total = sum(len(v) for v in mapping.values())
    print(f"Done. Anonymized {total} unique addresses/names:")
    print(f"  IPv4: {len(mapping['ipv4'])}")
    print(f"  IPv6: {len(mapping['ipv6'])}")
    print(f"  MAC:  {len(mapping['mac'])}")
    print(f"  DNS:  {len(mapping['dns'])}")


if __name__ == "__main__":
    main()
