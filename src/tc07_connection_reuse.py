#!/usr/bin/env python3
"""
TC-07 - Connection reuse and handshake cost.

Every response observed in this study carried 'Connection: close'.
This script determines whether the KME supports HTTP connection reuse,
and measures the cost of the mutual TLS handshake relative to the
request itself.

Uses Get status throughout, so no key material is consumed.

Usage:
    python tc07_connection_reuse.py <account_id> [iterations]
"""

import http.client
import json
import os
import ssl
import statistics
import sys
import time

KEYLOG = os.path.abspath("qukaydee-keys.log")
PATH = "/api/v1/keys/sae-2/status"


def context(account_id):
    ctx = ssl.create_default_context(
        cafile=f"account-{account_id}-server-ca-qukaydee-com.crt"
    )
    ctx.load_cert_chain(certfile="sae-1.crt", keyfile="sae-1.key")
    ctx.keylog_filename = KEYLOG
    return ctx


def host_for(account_id):
    return f"kme-1.acct-{account_id}.etsi-qkd-api.qukaydee.com"


def one_request(conn, headers):
    """Issue one request on an open connection. Returns (status, headers, seconds)."""
    t = time.perf_counter()
    conn.request("GET", PATH, headers=headers)
    resp = conn.getresponse()
    resp.read()
    return resp.status, dict(resp.getheaders()), time.perf_counter() - t


def part1_new_connection_each(account_id, n):
    """Baseline: a fresh connection per request. Splits handshake from request."""
    print(f"=== Part 1: {n} requests, new connection each ===")
    host = host_for(account_id)
    handshakes, requests = [], []

    for i in range(n):
        conn = http.client.HTTPSConnection(host, context=context(account_id))
        t = time.perf_counter()
        conn.connect()                      # TCP + full mutual TLS handshake
        hs = time.perf_counter() - t
        status, hdrs, rq = one_request(conn, {"Accept": "application/json"})
        conn.close()
        handshakes.append(hs)
        requests.append(rq)
        print(f"  [{i+1}] HTTP {status}  handshake {hs*1000:7.1f} ms  "
              f"request {rq*1000:6.1f} ms  Connection: {hdrs.get('Connection')}")

    hs_med = statistics.median(handshakes) * 1000
    rq_med = statistics.median(requests) * 1000
    print(f"\n  median handshake: {hs_med:.1f} ms")
    print(f"  median request:   {rq_med:.1f} ms")
    print(f"  handshake share:  {hs_med/(hs_med+rq_med)*100:.0f} % of total")
    return hs_med, rq_med


def part2_single_connection(account_id, n):
    """Attempt n requests over one connection."""
    print(f"\n=== Part 2: {n} requests, one connection ===")
    host = host_for(account_id)
    conn = http.client.HTTPSConnection(host, context=context(account_id))
    t = time.perf_counter()
    conn.connect()
    print(f"  handshake {(time.perf_counter()-t)*1000:.1f} ms")

    succeeded = 0
    for i in range(n):
        try:
            status, hdrs, rq = one_request(conn, {"Accept": "application/json"})
            succeeded += 1
            print(f"  [{i+1}] HTTP {status}  {rq*1000:6.1f} ms  "
                  f"Connection: {hdrs.get('Connection')}")
        except Exception as e:
            print(f"  [{i+1}] failed on reuse: {type(e).__name__}: {e}")
            break
    conn.close()
    print(f"\n  requests served on one connection: {succeeded} of {n}")
    return succeeded


def part3_explicit_keepalive(account_id):
    """Ask for keep-alive explicitly and record what the server answers."""
    print("\n=== Part 3: explicit Connection: keep-alive ===")
    host = host_for(account_id)
    conn = http.client.HTTPSConnection(host, context=context(account_id))
    conn.connect()
    status, hdrs, _ = one_request(
        conn, {"Accept": "application/json", "Connection": "keep-alive"}
    )
    conn.close()
    print(f"  HTTP {status}")
    print(f"  Connection:  {hdrs.get('Connection')}")
    print(f"  Keep-Alive:  {hdrs.get('Keep-Alive')}")
    print(f"  Server:      {hdrs.get('Server')}")
    return hdrs.get("Connection")


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: python tc07_connection_reuse.py <account_id> [iterations]")
    acct = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) == 3 else 5

    print(f"TLS key log -> {KEYLOG}\n")
    hs, rq = part1_new_connection_each(acct, n)
    served = part2_single_connection(acct, n)
    keepalive = part3_explicit_keepalive(acct)

    print("\n--- summary ---")
    print(f"connection reuse supported:  {'yes' if served > 1 else 'no'}")
    print(f"server Connection header:    {keepalive}")
    print(f"median handshake:            {hs:.1f} ms")
    print(f"median request:              {rq:.1f} ms")
    print(f"handshakes per key request:  {'1' if served <= 1 else '< 1'}")


if __name__ == "__main__":
    main()
