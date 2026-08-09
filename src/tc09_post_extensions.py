#!/usr/bin/env python3
"""
TC-09 - POST request form, multiple key IDs, and extension handling.

ETSI GS QKD 014 defines a POST form of Get key and Get key with key IDs,
carrying a JSON request body. The body may include:

  additional_slave_SAE_IDs   multicast delivery to several slave SAEs
  extension_mandatory        vendor parameters the KME MUST reject if
                             it does not understand them
  extension_optional         vendor parameters the KME may ignore

Only the GET form has been exercised so far in this study. This script
covers the POST form and the extension handling requirement.

Usage:
    python tc09_post_extensions.py <account_id> [additional_sae_id]
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
    """GET when body is None, POST otherwise. Returns (status, parsed)."""
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
    text = json.dumps(body, indent=2)
    print(text[:900] + ("\n  ...(truncated)" if len(text) > 900 else ""))


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: python tc09_post_extensions.py <account_id> [additional_sae_id]")
    acct = sys.argv[1]
    extra_sae = sys.argv[2] if len(sys.argv) == 3 else None

    print(f"TLS key log -> {KEYLOG}\n")
    results = []

    # --- A: POST form of Get key, equivalent to the GET already tested ---
    code, body = request(acct, "kme-1", "sae-1", "sae-2/enc_keys",
                         {"number": 2, "size": 512})
    show("A", "POST Get key (plain)", code, body)
    results.append(("A", "POST enc_keys", code, body.get("message", "ok")))
    key_ids = [k["key_ID"] for k in body.get("keys", [])] if code == 200 else []

    # --- B: POST Get key with key IDs, several identifiers in one call ---
    if len(key_ids) >= 2:
        code, body = request(acct, "kme-2", "sae-2", "sae-1/dec_keys",
                             {"key_IDs": [{"key_ID": k} for k in key_ids]})
        show("B", f"POST Get key with {len(key_ids)} key IDs", code, body)
        returned = len(body.get("keys", [])) if code == 200 else 0
        results.append(("B", "multi key_ID", code, f"{returned} keys returned"))
    else:
        results.append(("B", "multi key_ID", None, "skipped - part A failed"))

    # --- C: unknown extension_optional, must be ignored ---
    code, body = request(acct, "kme-1", "sae-1", "sae-2/enc_keys",
                         {"number": 1, "size": 512,
                          "extension_optional": [
                              {"eclaireur_test_optional": "ignore-me"}]})
    show("C", "POST with unknown extension_optional", code, body)
    results.append(("C", "unknown optional ext", code,
                    "accepted" if code == 200 else body.get("message")))

    # --- D: unknown extension_mandatory, MUST be rejected ---
    code, body = request(acct, "kme-1", "sae-1", "sae-2/enc_keys",
                         {"number": 1, "size": 512,
                          "extension_mandatory": [
                              {"eclaireur_test_mandatory": "must-reject"}]})
    show("D", "POST with unknown extension_mandatory", code, body)
    results.append(("D", "unknown mandatory ext", code,
                    "ACCEPTED - see notes" if code == 200 else body.get("message")))

    # --- E: multicast, only if a third SAE was supplied ---
    if extra_sae:
        code, body = request(acct, "kme-1", "sae-1", "sae-2/enc_keys",
                             {"number": 1, "size": 512,
                              "additional_slave_SAE_IDs": [extra_sae]})
        show("E", f"POST with additional_slave_SAE_IDs [{extra_sae}]", code, body)
        results.append(("E", "multicast", code,
                        "accepted" if code == 200 else body.get("message")))
    else:
        results.append(("E", "multicast", None, "skipped - no SAE supplied"))

    print("\n--- summary ---")
    print(f"{'case':<6}{'condition':<24}{'status':<8}{'result'}")
    for tag, cond, code, note in results:
        print(f"{tag:<6}{cond:<24}{str(code):<8}{note}")

    print("\nConformance note: case D must be rejected. ETSI GS QKD 014 requires")
    print("a KME to refuse a request carrying an extension_mandatory parameter")
    print("it does not support. A 200 there is a conformance finding.")


if __name__ == "__main__":
    main()
