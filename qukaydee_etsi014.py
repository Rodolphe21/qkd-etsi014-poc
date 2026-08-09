#!/usr/bin/env python3
"""
ETSI GS QKD 014 test client for QuKayDee.

Walks the full master -> slave key delivery flow across two KMEs and writes a
TLS key log that Wireshark can use to decrypt the capture.

Stdlib only. Run from the directory holding your certs:
    account-<N>-server-ca-qukaydee-com.crt
    sae-1.crt / sae-1.key
    sae-2.crt / sae-2.key

Usage:
    python qukaydee_etsi014.py <account_id>
"""

import json
import os
import ssl
import sys
import urllib.error
import urllib.request

KEYLOG = os.path.abspath("qukaydee-keys.log")
KEY_SIZE = 1024
KEY_COUNT = 2


def context(account_id, sae):
    """SSL context for one SAE identity, with TLS secrets logged for Wireshark."""
    ctx = ssl.create_default_context(
        cafile=f"account-{account_id}-server-ca-qukaydee-com.crt"
    )
    ctx.load_cert_chain(certfile=f"{sae}.crt", keyfile=f"{sae}.key")
    # Set explicitly rather than relying on the SSLKEYLOGFILE env var.
    ctx.keylog_filename = KEYLOG
    return ctx


def call(account_id, kme, sae, path):
    """One ETSI 014 request. Returns (status_code, parsed_body)."""
    url = (
        f"https://{kme}.acct-{account_id}.etsi-qkd-api.qukaydee.com"
        f"/api/v1/keys/{path}"
    )
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, context=context(account_id, sae)) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"raw": body}


def show(label, code, body):
    print(f"\n--- {label}  [HTTP {code}] ---")
    print(json.dumps(body, indent=2))


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python qukaydee_etsi014.py <account_id>")
    acct = sys.argv[1]

    print(f"TLS key log -> {KEYLOG}")
    print("Point Wireshark at it: Preferences > Protocols > TLS >")
    print("  (Pre)-Master-Secret log filename\n")

    # 1. Get status - capability negotiation, master side.
    code, status = call(acct, "kme-1", "sae-1", "sae-2/status")
    show("Get status (kme-1, as sae-1)", code, status)
    if code != 200:
        sys.exit("status failed - check certs, account id and topology")

    # 2. Get key - master SAE requests key material.
    code, enc = call(
        acct, "kme-1", "sae-1",
        f"sae-2/enc_keys?number={KEY_COUNT}&size={KEY_SIZE}",
    )
    show(f"Get key ({KEY_COUNT} x {KEY_SIZE} bits)", code, enc)
    if code != 200 or not enc.get("keys"):
        sys.exit("enc_keys failed")

    first = enc["keys"][0]
    key_id = first["key_ID"]

    # 3. Get key with key IDs - slave SAE, OTHER KME, OTHER cert.
    #    Only the key ID crossed between them; the key material did not.
    code, dec = call(acct, "kme-2", "sae-2", f"sae-1/dec_keys?key_ID={key_id}")
    show("Get key with key IDs (kme-2, as sae-2)", code, dec)

    if code == 200 and dec.get("keys"):
        match = dec["keys"][0]["key"] == first["key"]
        print(f"\n>>> key material identical across KMEs: {match}")

    # 4. Replay the same key ID. ETSI post-condition: a delivered key leaves
    #    the pool, so this should fail. If it succeeds, that is worth knowing.
    code, replay = call(acct, "kme-2", "sae-2", f"sae-1/dec_keys?key_ID={key_id}")
    show("Replay same key_ID (expect failure)", code, replay)
    print(f"\n>>> replay rejected: {code != 200}")

    # 5. Negative: size above max_key_size advertised by status.
    too_big = status.get("max_key_size", 100000) + 8
    code, err = call(acct, "kme-1", "sae-1", f"sae-2/enc_keys?number=1&size={too_big}")
    show(f"Oversized request ({too_big} bits, expect 4xx)", code, err)

    # 6. Negative: more keys than max_key_per_request.
    too_many = status.get("max_key_per_request", 100) + 1
    code, err = call(acct, "kme-1", "sae-1", f"sae-2/enc_keys?number={too_many}&size=256")
    show(f"Too many keys ({too_many}, expect 4xx)", code, err)

    print(f"\nDone. Key log written to {KEYLOG}")


if __name__ == "__main__":
    main()
