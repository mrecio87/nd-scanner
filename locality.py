#!/usr/bin/env python3
"""Decide whether a target list is entirely on directly-attached subnets.

Prints "local" or "routed".

"local" means nothing sits between the appliance and the targets, so SYN
scanning is safe and can run fast. "routed" means at least one target is behind
a router or firewall, where SYN scanning creates state-table churn that gets the
appliance blocked, and a connect scan is both safer and more accurate.

Anything uncertain resolves to "routed": under-scanning is recoverable, getting
the appliance blocked mid-engagement is not.

Usage:  locality.py <comma-separated-cidrs> <targets-file>
"""
import ipaddress
import socket
import sys


def local_networks(spec):
    nets = []
    for raw in (spec or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            pass
    return nets


def addresses_for(target):
    """Every address a target line refers to, or None if it cannot be resolved."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [net]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_network(info[4][0] + "/32", strict=False))
        except ValueError:
            pass
    return out or None


def main():
    if len(sys.argv) < 3:
        print("routed")
        return
    nets = local_networks(sys.argv[1])
    if not nets:
        print("routed")
        return

    try:
        with open(sys.argv[2]) as fh:
            targets = [l.strip() for l in fh if l.strip()]
    except OSError:
        print("routed")
        return

    if not targets:
        print("routed")
        return

    for target in targets:
        addrs = addresses_for(target)
        if not addrs:
            print("routed")     # unresolvable, so assume it is not next door
            return
        for addr in addrs:
            if not any(addr.subnet_of(net) for net in nets
                       if addr.version == net.version):
                print("routed")
                return

    print("local")


if __name__ == "__main__":
    main()
