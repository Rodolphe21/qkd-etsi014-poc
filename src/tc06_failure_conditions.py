#!/usr/bin/env python3
"""
TC-06 - Failure condition discrimination.

ETSI GS QKD 014 returns a single error object for retrieval failures.
This script produces four distinct failure conditions against the same
endpoint and compares the responses to determine whether an SAE can
tell them apart.

Conditions:
  A  consumed        key delivered once, requested again
  B  expired         key left unfetched past the key stream expiry
  C  never issued    syntactically valid UUID that was never assigned
  D  malformed       not a UUID at all

Requires key expiry set to a short value in the portal (120 s suggested).

Usage:
    python tc06_failure_conditions.py <account_id> [expiry_seconds]
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

KEYLOG = os.path.abspath("qukaydee-keys.log")
UNKNOWN_UUID = "00000000-0000-0000-0000-000000000000"
MALFORMED_ID = "not-a-uuid"


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


def get_key(account_id):
    """Request one key from kme-1 as sae-1. Returns key_ID."""
    code, body = call(account_id, "kme-1", "sae-1",
                      "sae-2/enc_keys?number=1&size=256")
    if code != 200:
        sys.exit(f"enc_keys failed: {code} {body}")
    return body["keys"][0]["key_ID"]


def retrieve(account_id, key_id):
    """Attempt retrieval from kme-2 as sae-2."""
    return call(account_id, "kme-2", "sae-2", f"sae-1/dec_keys?key_ID={key_id}")


def show(tag, label, code, body):
    print(f"\n--- {tag}: {label}  [HTTP {code}] ---")
    print(json.dumps(body, indent=2))


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: python tc06_failure_conditions.py <account_id> [expiry_seconds]")
    acct = sys.argv[1]
    expiry = int(sys.argv[2]) if len(sys.argv) == 3 else 120
    wait = expiry + 30

    print(f"TLS key log -> {KEYLOG}")
    print(f"Assuming key expiry of {expiry} s; will wait {wait} s for condition B.\n")

    # Pool state before, for the generation-vs-assignment question.
    code, status = call(acct, "kme-1", "sae-1", "sae-2/status")
    print(f"stored_key_count before: {status.get('stored_key_count')}")

    # --- B: request the key that will be left to expire, first ---
    expiring_id = get_key(acct)
    t_start = time.time()
    print(f"key for condition B issued: {expiring_id}")

    # --- A: consumed ---
    consumed_id = get_key(acct)
    code, body = retrieve(acct, consumed_id)
    if code != 200:
        sys.exit(f"initial retrieval failed unexpectedly: {code} {body}")
    code, body = retrieve(acct, consumed_id)
    show("A", "consumed (delivered, requested again)", code, body)
    results = [("A", "consumed", code, body.get("message"))]

    # --- C: never issued ---
    code, body = retrieve(acct, UNKNOWN_UUID)
    show("C", "never issued (valid UUID, never assigned)", code, body)
    results.append(("C", "never issued", code, body.get("message")))

    # --- D: malformed ---
    code, body = retrieve(acct, MALFORMED_ID)
    show("D", "malformed (not a UUID)", code, body)
    results.append(("D", "malformed", code, body.get("message")))

    # --- B: expired ---
    remaining = wait - (time.time() - t_start)
    if remaining > 0:
        print(f"\nwaiting {int(remaining)} s for the key to expire...")
        time.sleep(remaining)
    code, body = retrieve(acct, expiring_id)
    show("B", "expired (never fetched, past expiry)", code, body)
    results.insert(1, ("B", "expired", code, body.get("message")))

    code, status = call(acct, "kme-1", "sae-1", "sae-2/status")
    print(f"\nstored_key_count after: {status.get('stored_key_count')}")

    print("\n--- summary ---")
    print(f"{'case':<6}{'condition':<16}{'status':<8}{'message'}")
    for tag, cond, code, msg in results:
        print(f"{tag:<6}{cond:<16}{str(code):<8}{msg}")

    codes = {code for _, _, code, _ in results}
    msgs = {msg for _, _, _, msg in results}
    print(f"\ndistinct status codes: {len(codes)} of 4")
    print(f"distinct messages:     {len(msgs)} of 4")


if __name__ == "__main__":
    main()
