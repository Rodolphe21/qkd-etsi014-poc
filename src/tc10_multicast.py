#!/usr/bin/env python3
"""
TC-09 case E - multicast key delivery, completed.

Requests one key with additional_slave_SAE_IDs, then attempts retrieval
by BOTH slave SAEs from their respective KMEs, and compares the key
material returned.

Accepting the parameter is not the same as delivering the key. This
script tests the delivery.

Usage:
    python tc09e_multicast.py <account_id>
"""

import json
import os
import ssl
import sys
import urllib.error
import urllib.request

KEYLOG = os.path.abspath("qukaydee-keys.log")


def context(account_id, sae):
    ctx = ssl.create_default_context(
        cafile=f"account-{account_id}-server-ca-qukaydee-com.crt"
    )
    ctx.load_cert_chain(certfile=f"{sae}.crt", keyfile=f"{sae}.key")
    ctx.keylog_filename = KEYLOG
    return ctx


def request(account_id, kme, sae, path, body=None):
    url = (
        f"https://{kme}.acct-{account_id}.etsi-qkd-api.qukaydee.com"
        f"/api/v1/keys/{path}"
    )
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, context=context(account_id, sae)) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"raw": raw[:400]}


def show(tag, label, code, body):
    print(f"\n--- {tag}: {label}  [HTTP {code}] ---")
    print(json.dumps(body, indent=2)[:700])


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python tc09e_multicast.py <account_id>")
    acct = sys.argv[1]
    print(f"TLS key log -> {KEYLOG}\n")

    # 1. Master requests one key for sae-2, additionally for sae-3.
    code, body = request(acct, "kme-1", "sae-1", "sae-2/enc_keys",
                         {"number": 1, "size": 512,
                          "additional_slave_SAE_IDs": ["sae-3"]})
    show("E1", "master Get key with additional_slave_SAE_IDs", code, body)
    if code != 200 or not body.get("keys"):
        sys.exit("multicast request refused; nothing further to test")

    key_id = body["keys"][0]["key_ID"]
    master_key = body["keys"][0]["key"]
    print(f"\nkey_ID: {key_id}")

    # 2. First slave retrieves from its own KME.
    code2, b2 = request(acct, "kme-2", "sae-2",
                        f"sae-1/dec_keys?key_ID={key_id}")
    show("E2", "sae-2 retrieves from kme-2", code2, b2)
    k2 = b2["keys"][0]["key"] if code2 == 200 and b2.get("keys") else None

    # 3. Second slave retrieves from its own KME.
    code3, b3 = request(acct, "kme-3", "sae-3",
                        f"sae-1/dec_keys?key_ID={key_id}")
    show("E3", "sae-3 retrieves from kme-3", code3, b3)
    k3 = b3["keys"][0]["key"] if code3 == 200 and b3.get("keys") else None

    print("\n--- summary ---")
    print(f"{'step':<6}{'actor':<22}{'status':<8}{'key matches master'}")
    print(f"{'E1':<6}{'sae-1 @ kme-1':<22}{200:<8}{'-'}")
    print(f"{'E2':<6}{'sae-2 @ kme-2':<22}{str(code2):<8}"
          f"{k2 == master_key if k2 else 'no key returned'}")
    print(f"{'E3':<6}{'sae-3 @ kme-3':<22}{str(code3):<8}"
          f"{k3 == master_key if k3 else 'no key returned'}")

    if k2 and k3 and k2 == k3 == master_key:
        print("\nMulticast delivery confirmed: one key, three parties, "
              "only the identifier shared.")
    else:
        print("\nMulticast NOT confirmed - the parameter was accepted but "
              "the key was not delivered to both slaves.")


if __name__ == "__main__":
    main()
