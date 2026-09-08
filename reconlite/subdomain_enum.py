"""
subdomain_enum.py

Two subdomain discovery techniques:
1. DNS brute-force using a wordlist (active, works offline against your own DNS)
2. Certificate Transparency lookup via crt.sh (passive, no packets sent to target)

Usage:
    python -m reconlite.subdomain_enum example.com --wordlist wordlists/small.txt
"""

from __future__ import annotations

import argparse
import concurrent.futures
import socket
from collections.abc import Iterable
from dataclasses import dataclass

import requests


@dataclass
class SubdomainResult:
    subdomain: str
    ip_addresses: list[str]
    source: str  # "bruteforce" or "crtsh"


def _resolve(hostname: str) -> list[str]:
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(hostname, None)})
    except socket.gaierror:
        return []


def brute_force(domain: str, wordlist: Iterable[str], max_workers: int = 50) -> list[SubdomainResult]:
    """Try each word in the wordlist as a subdomain prefix and resolve it."""
    candidates = [f"{word.strip()}.{domain}" for word in wordlist if word.strip()]
    found: list[SubdomainResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_host = {pool.submit(_resolve, host): host for host in candidates}
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            ips = future.result()
            if ips:
                found.append(SubdomainResult(host, ips, "bruteforce"))

    return sorted(found, key=lambda r: r.subdomain)


def crtsh_lookup(domain: str, timeout: int = 15) -> list[SubdomainResult]:
    """Query crt.sh certificate transparency logs for subdomains. Passive - no
    traffic ever touches the target itself."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        entries = resp.json()
    except (requests.RequestException, ValueError):
        return []

    names: set[str] = set()
    for entry in entries:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.")
            if name.endswith(domain):
                names.add(name)

    results = []
    for name in sorted(names):
        results.append(SubdomainResult(name, ip_addresses=[], source="crtsh"))
    return results


def enumerate_subdomains(domain: str, wordlist_path: str | None, resolve_crtsh: bool = True) -> list[SubdomainResult]:
    results: list[SubdomainResult] = []

    if wordlist_path:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            words = f.readlines()
        results.extend(brute_force(domain, words))

    if resolve_crtsh:
        crt_results = crtsh_lookup(domain)
        # Resolve IPs for anything crt.sh found that brute-force missed
        known = {r.subdomain for r in results}
        for r in crt_results:
            if r.subdomain not in known:
                r.ip_addresses = _resolve(r.subdomain)
                results.append(r)

    return sorted(results, key=lambda r: r.subdomain)


def main() -> None:
    parser = argparse.ArgumentParser(description="Enumerate subdomains for a target domain.")
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("--wordlist", help="Path to a subdomain wordlist file", default=None)
    parser.add_argument("--no-crtsh", action="store_true", help="Skip crt.sh passive lookup")
    args = parser.parse_args()

    results = enumerate_subdomains(args.domain, args.wordlist, resolve_crtsh=not args.no_crtsh)

    for r in results:
        ip_str = ", ".join(r.ip_addresses) if r.ip_addresses else "unresolved"
        print(f"[{r.source:10}] {r.subdomain:40} {ip_str}")

    print(f"\nTotal unique subdomains found: {len(results)}")


if __name__ == "__main__":
    main()
