#!/usr/bin/env python3
"""
TC-04 - SAE identity binding and authorisation layering.

Issues the same Get key request four times, varying only the client
certificate, and records at which layer each identity is rejected:
TLS transport, or ETSI 014 application.

Run from the directory holding the certificates:
    python tc04_identity.py <account_id>
"""

import json
import os
import ssl
import sys
import urllib.error
import urllib.request

KEYLOG = os.path.abspath("qukaydee-keys.log")

CASES = [
    ("A", "sae-1",        "control - registered master SAE"),
    ("B", "sae-2",        "registered SAE, not master on this KME"),
    ("C", "sae-9",        "trusted CA, identity not registered"),
    ("D", "rogue-sae-1",  "untrusted CA, CN=sae-1"),
]


def context(account_id, cert):
    ctx = ssl.create_default_context(
        cafile=f"account-{account_id}-server-ca-qukaydee-com.crt"
    )
    ctx.load_cert_chain(certfile=f"{cert}.crt", keyfile=f"{cert}.key")
    ctx.keylog_filename = KEYLOG
    return ctx


def attempt(account_id, cert):
    """Return (layer, code, body) where layer is 'tls', 'http' or 'none'."""
    url = (
        f"https://kme-1.acct-{account_id}.etsi-qkd-api.qukaydee.com"
        f"/api/v1/keys/sae-2/enc_keys?number=1&size=256"
    )
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, context=context(account_id, cert)) as r:
            return "http", r.status, json.load(r)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return "http", e.code, json.loads(raw)
        except json.JSONDecodeError:
            return "http", e.code, {"raw": raw[:200]}
    except urllib.error.URLError as e:
        # TLS failure, connection reset, or certificate rejection by the peer.
        return "tls", None, {"error": str(e.reason)}
    except ssl.SSLError as e:
        return "tls", None, {"error": str(e)}
    except OSError as e:
        return "tls", None, {"error": str(e)}


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python tc04_identity.py <account_id>")
    acct = sys.argv[1]

    print(f"TLS key log -> {KEYLOG}\n")
    results = []

    for tag, cert, note in CASES:
        print(f"=== Case {tag}: {cert} ({note}) ===")
        layer, code, body = attempt(acct, cert)
        if layer == "tls":
            print(f"  rejected at TLS layer: {body['error']}")
        else:
            print(f"  HTTP {code}")
            print("  " + json.dumps(body)[:300])
        results.append((tag, cert, layer, code))
        print()

    print("--- summary ---")
    print(f"{'case':<6}{'certificate':<16}{'layer':<8}{'status'}")
    for tag, cert, layer, code in results:
        status = code if code is not None else "handshake failed"
        print(f"{tag:<6}{cert:<16}{layer:<8}{status}")


if __name__ == "__main__":
    main()
