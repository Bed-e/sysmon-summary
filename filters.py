"""Step 3: skip IOCs that cannot produce a useful answer.

Skipping is not ranking (that is scoring/). A skipped IOC is never sent
to an API, but it stays visible in the report with its reason code.
Hashes are never skipped: a trusted path is only a weak ranking signal
(see scoring/).

Reason codes:
    ip_not_public, ip_known_shared_range, dns_internal

The result of split_iocs is a tuple (to_rank, skipped):
    to_rank: [{"type": "ip", "value": "8.8.8.8", "record": {...}}, ...]
    skipped: [{"type": "ip", "value": "10.0.0.5", "reason": "ip_not_public",
               "record": {...}}, ...]
"""

import ipaddress
import os

# Name endings that mean "internal". A single-label name is checked apart.
INTERNAL_SUFFIXES = [".local", ".lan", ".internal", ".home", ".arpa"]

# Carrier-grade NAT range. ipaddress does not treat it as private.
CGNAT = ipaddress.ip_network("100.64.0.0/10")


def load_list(path):
    """Read a text file into a list of lines. Blank lines and lines starting
    with # are dropped. A missing file gives an empty list.
    """
    if not os.path.exists(path):
        return []
    items = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#"):
                items.append(line)
    return items


def load_config(data_dir="data"):
    """Load the four list files from data_dir into one dict:
        {"ranges": [ip_network, ...], "ad_domains": [...],
         "trusted_paths": [lowercase paths], "well_known": [...]}
    A bad CIDR line is skipped, not fatal. trusted_paths and well_known are
    used by scoring/; they are loaded here so all lists load in one place.
    """
    ranges = []
    for text in load_list(os.path.join(data_dir, "shared_ranges.txt")):
        try:
            ranges.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue

    ad_domains = []
    for text in load_list(os.path.join(data_dir, "ad_domains.txt")):
        ad_domains.append(text.lower().strip("."))

    trusted_paths = []
    for text in load_list(os.path.join(data_dir, "trusted_paths.txt")):
        trusted_paths.append(text.lower())

    well_known = []
    for text in load_list(os.path.join(data_dir, "well_known_names.txt")):
        well_known.append(text.lower())

    return {
        "ranges": ranges,
        "ad_domains": ad_domains,
        "trusted_paths": trusted_paths,
        "well_known": well_known,
    }


def is_ip_not_public(ip):
    """True for private, loopback, link-local, multicast, reserved, CGNAT,
    unspecified (0.0.0.0) and the broadcast address. `ip` is an IPv4 string.
    """
    address = ipaddress.ip_address(ip)
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address in CGNAT
        or ip == "255.255.255.255"
    )


def is_ip_in_shared_range(ip, ranges):
    """True if the IPv4 string is inside any network in `ranges`."""
    address = ipaddress.ip_address(ip)
    for network in ranges:
        if address in network:
            return True
    return False


def is_dns_internal(name, ad_domains):
    """True if the name is a single label, ends in an internal suffix, or
    is (or ends in) one of our own AD domains.
    """
    if "." not in name:
        return True
    for suffix in INTERNAL_SUFFIXES:
        if name.endswith(suffix):
            return True
    for domain in ad_domains:
        if name == domain or name.endswith("." + domain):
            return True
    return False


def skip_reason(ioc_type, value, config):
    """Return the reason code for a skipped IOC, or None if it is kept."""
    if ioc_type == "ip":
        if is_ip_not_public(value):
            return "ip_not_public"
        if is_ip_in_shared_range(value, config["ranges"]):
            return "ip_known_shared_range"
    elif ioc_type == "dns":
        if is_dns_internal(value, config["ad_domains"]):
            return "dns_internal"
    return None


def split_iocs(iocs, config):
    """Split collect_iocs output into (to_rank, skipped)."""
    to_rank = []
    skipped = []

    for ioc_type in ["ip", "dns", "hash"]:
        for value, record in iocs[ioc_type].items():
            item = {"type": ioc_type, "value": value, "record": record}
            reason = skip_reason(ioc_type, value, config)
            if reason is None:
                to_rank.append(item)
            else:
                item["reason"] = reason
                skipped.append(item)

    return to_rank, skipped
