#!/usr/bin/env python3
"""
TC-08 - Key store exhaustion and replenishment.

Requests key material faster than the key stream produces it, until the
key store is empty, and records what the KME returns. Then observes
replenishment to derive an effective key generation rate.

Note: draining the pool leaves the topology without keys for several
minutes. Run this when no other test case needs key material.

Usage:
    python tc08_exhaustion.py <account_id> [max_requests] [recovery_samples]
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

KEYLOG = os.path.abspath("qukaydee-keys.log")
RECOVERY_INTERVAL = 15  # seconds between status polls during refill


def context(account_id, sae):
    ctx = ssl.create_default_context(
        cafile=f"account-{account_id}-server-ca-qukaydee-com.crt"
    )
    ctx.load_cert_chain(certfile=f"{sae}.crt", keyfile=f"{sae}.key")
    ctx.keylog_filename = KEYLOG
    return ctx


def call(account_id, kme, sae, path):
    url = (
        f"https://{kme}.acct-{account_id}.etsi-qkd-api.qukaydee.com"
        f"/api/v1/keys/{path}"
    )
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, context=context(account_id, sae)) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"raw": raw[:300]}


def status(account_id):
    return call(account_id, "kme-1", "sae-1", "sae-2/status")


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: python tc08_exhaustion.py <account_id> [max_requests] [recovery_samples]")
    acct = sys.argv[1]
    max_requests = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    recovery_samples = int(sys.argv[3]) if len(sys.argv) > 3 else 8

    print(f"TLS key log -> {KEYLOG}\n")

    code, st = status(acct)
    if code != 200:
        sys.exit(f"status failed: {code} {st}")
    key_size = st["key_size"]
    per_request = st["max_key_per_request"]
    start_count = st["stored_key_count"]
    print("=== Baseline ===")
    print(f"  key_size            {key_size}")
    print(f"  max_key_per_request {per_request}")
    print(f"  stored_key_count    {start_count}")
    print(f"  max_key_count       {st['max_key_count']}\n")

    print(f"=== Drain: requesting {per_request} x {key_size} bits per call ===")
    delivered = 0
    trajectory = []
    error = None

    for i in range(1, max_requests + 1):
        code, body = call(
            acct, "kme-1", "sae-1",
            f"sae-2/enc_keys?number={per_request}&size={key_size}",
        )
        if code != 200:
            error = (code, body)
            print(f"  [{i:3}] HTTP {code}  <- store exhausted")
            print("  " + json.dumps(body, indent=2).replace("\n", "\n  "))
            break
        got = len(body.get("keys", []))
        delivered += got
        _, st = status(acct)
        remaining = st.get("stored_key_count")
        trajectory.append((i, got, remaining))
        print(f"  [{i:3}] HTTP 200  keys {got:4}  stored_key_count {remaining}")
        if remaining == 0:
            print("  store reports zero; next request should fail")

    print(f"\n  keys delivered before exhaustion: {delivered}")
    print(f"  requests issued:                 {len(trajectory)}")
    if error is None:
        print(f"  NOTE: no error reached within {max_requests} requests")

    # --- partial delivery check -------------------------------------------
    partials = [(i, got) for i, got, _ in trajectory if got < per_request]
    if partials:
        print(f"\n  partial deliveries (fewer keys than requested): {partials}")
        print("  -> the KME degrades by serving fewer keys rather than failing")
    else:
        print("\n  no partial deliveries: every successful request was fully served")

    # --- recovery ---------------------------------------------------------
    print(f"\n=== Replenishment: {recovery_samples} samples every {RECOVERY_INTERVAL} s ===")
    samples = []
    t0 = time.time()
    for i in range(recovery_samples):
        time.sleep(RECOVERY_INTERVAL)
        _, st = status(acct)
        elapsed = time.time() - t0
        count = st.get("stored_key_count")
        samples.append((elapsed, count))
        print(f"  t+{elapsed:6.1f} s  stored_key_count {count}")

    if len(samples) >= 2:
        dt = samples[-1][0] - samples[0][0]
        dk = samples[-1][1] - samples[0][1]
        if dt > 0:
            rate_keys = dk / dt
            print(f"\n  observed replenishment: {rate_keys:.2f} keys/s "
                  f"= {rate_keys * key_size:.0f} bits/s")
            print(f"  configured key stream rate: 1000 bits/s")

    print("\n--- summary ---")
    print(f"exhaustion reached:  {'yes' if error else 'no'}")
    if error:
        print(f"status code:         {error[0]}")
        print(f"message:             {error[1].get('message')}")
    print(f"keys delivered:      {delivered}")


if __name__ == "__main__":
    main()
