"""Step 6 (enrichability): tag the IOCs that must not be sent to a portal.

Every IOC stays visible, ranked and in its chain. The tag only says why a
lookup would not be made (design.md section 6):
    ip_not_public, ip_known_shared_range   nothing to gain
    dns_internal                           must not send (privacy)
Hashes are always enrichable. enrich.enrich_one checks the tag again right
before any call.

The result of list_iocs is a flat list:
    [{"type": "ip", "value": "10.0.0.5", "record": {...},
      "not_enrichable": "ip_not_public"}, ...]
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
    """Load the three list files from data_dir into one dict:
        {"ranges": [ip_network, ...], "ad_domains": [...], "well_known": [...]}
    A bad CIDR line is skipped, not fatal. well_known is used by scoring/;
    it is loaded here so all lists load in one place.
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

    well_known = []
    for text in load_list(os.path.join(data_dir, "well_known_names.txt")):
        well_known.append(text.lower())

    return {
        "ranges": ranges,
        "ad_domains": ad_domains,
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


def not_enrichable_reason(ioc_type, value, config):
    """Say why one IOC must not be sent to a portal, if it must not.

    Input: ioc_type ("ip", "dns" or "hash") and value, from iocs.collect_iocs;
    config from load_config (ranges and ad_domains are used).
    Output: "ip_not_public" or "ip_known_shared_range" (nothing to gain),
    "dns_internal" (must not send), or "" when it can be enriched. Hashes
    are always enrichable.
    Used by: list_iocs.
    """
    if ioc_type == "ip":
        if is_ip_not_public(value):
            return "ip_not_public"
        if is_ip_in_shared_range(value, config["ranges"]):
            return "ip_known_shared_range"
    elif ioc_type == "dns":
        if is_dns_internal(value, config["ad_domains"]):
            return "dns_internal"
    return ""


def list_iocs(iocs, config):
    """Turn collect_iocs output into one flat list, each IOC tagged.

    Input: iocs from iocs.collect_iocs; config from load_config.
    Output: a list of {"type", "value", "record", "not_enrichable"}, every
    IOC once (ips, then dns names, then hashes). not_enrichable is the
    reason code from not_enrichable_reason, or "". Nothing is removed: an
    IOC that cannot be enriched is still ranked and shown.
    Used by: web.enrich_jobs.make_state, which hands it to
    scoring.ranking.rank_iocs.
    """
    items = []
    for ioc_type in ["ip", "dns", "hash"]:
        for value, record in iocs[ioc_type].items():
            items.append({"type": ioc_type, "value": value, "record": record,
                          "not_enrichable": not_enrichable_reason(ioc_type, value, config)})
    return items
