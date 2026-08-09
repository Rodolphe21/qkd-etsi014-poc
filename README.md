# qkd-etsi014-poc

Wire-level analysis of the **ETSI GS QKD 014** key delivery API — the REST
interface an encryptor or VPN gateway uses to fetch keys from a QKD network.

Ten test cases, six packet captures, TLS decrypted so that both the API
exchanges and the handshake underneath are visible. Everything here is
reproducible in about twenty minutes.

📄 **[Full report](docs/ETSI014_PoC_Report_v9.docx)** — 14 sections, 17 figures.

---

## Scope

Testing was performed against [QuKayDee](https://qukaydee.com), a hosted QKD
network simulator. There are no physical quantum links, and the platform states
plainly that its keys are not cryptographically secure and that it is intended
for education and API testing.

Accordingly:

- Findings about **message structure, error behaviour and the mutual TLS
  identity model** follow from the specification and are expected to generalise.
- Findings about **specific parameter values and the observed TLS posture**
  characterise that one implementation only.
- A third class concerns **behaviour the specification neither defines nor
  constrains**. Where such a case is recorded, the observation is that the
  standard leaves the choice open — not that any particular choice is correct.

Not covered: the quantum layer, KME-to-KME synchronisation (proprietary and not
exposed), trusted-node relay, and the other ETSI QKD deliverables (004, 015,
018, 020), which are referenced but not tested.

---

## Results

| TC | Objective | Outcome |
|----|-----------|---------|
| 01 | Cross-KME key delivery integrity | Pass |
| 02 | Key consumption and replay rejection | Pass |
| 03 | Request parameter validation | Pass |
| 04 | SAE identity binding and authorisation layering | **Contrary to expectation** |
| 05 | TLS cryptographic posture | Characterisation |
| 06 | Failure condition discrimination | **Contrary to expectation** |
| 07 | Connection reuse and handshake cost | **Contrary to expectation** |
| 08 | Key store exhaustion and replenishment | Pass, with a semantic finding |
| 09 | POST form and extension handling | Pass |
| 10 | Multicast key delivery | Pass |

Three findings worth the click:

**Access control is a client certificate and nothing else.** No token, no
password, no session. The SAE's identity is established during the mutual TLS
handshake and never restated. In this implementation the TLS layer did not make
the decision — all four test identities completed the handshake, including one
signed by an unregistered CA, and every rejection came from the application
behind it.

**The standard mandates behaviour it provides no way to report.** A delivered
key must leave the key store, and an expired key must not be served — yet the
status codes carrying both conditions lie outside the set ETSI 014 defines.
Each implementation must invent its own signalling for something the standard
requires.

**The extension mechanism works exactly as specified.** An unknown
`extension_mandatory` is refused, an unknown `extension_optional` ignored.
Vendor extensions are the principal route by which conformant implementations
diverge, so this requirement is what the mechanism rests on — and it holds.

### Three corrections

Three of the ten test cases returned results contradicting what had been
inferred from reading the specification. Two of those inferences had already
been written into the report as findings before being tested:

- Expiry proved **distinguishable** from consumption (403, not 404).
- Connection reuse proved **available** — the `Connection: close` observed
  earlier came from the test client, not the KME.
- Key store depletion returned **400**, not the 503 the specification's error
  set would suggest.

The wrong expectations are retained in the report rather than quietly
rewritten. A specification read carefully is not a specification tested.

---

## Reproducing

### 1. Platform

Create a free [QuKayDee](https://qukaydee.com) account and build the topology:

| Element | Configuration |
|---|---|
| KMEs | `kme-1`, `kme-2` (and `kme-3` for TC-10) |
| SAEs | `sae-1` → kme-1, `sae-2` → kme-2 (and `sae-3` → kme-3). Leave the DN at its default `CN=sae-<n>` |
| Key stream | sae-1 ↔ sae-2, 1000 bits/s, expiry 600 s (plus a three-party stream for TC-10) |

Download the server CA certificate from **API → Download Server CA
Certificate**. The filename contains your account ID; every script takes it as
an argument.

### 2. Certificates

Generated with
[qukaydee-generate-client-certificates](https://github.com/brunorijsman/qukaydee-generate-client-certificates).
Running them inside a container avoids the CRLF and path-rewriting problems
that shell scripts hit on Windows:

```bash
git clone https://github.com/brunorijsman/qukaydee-generate-client-certificates.git

docker run --rm -v "$(pwd):/work" -w /work python:3.12-slim bash -c "
  cd qukaydee-generate-client-certificates &&
  sed -i 's/\r\$//' *.sh &&
  bash ./generate-client-root-ca-certificate-and-key.sh &&
  for s in sae-1 sae-2 sae-3 sae-9; do
    bash ./generate-client-sae-certificate-and-key.sh \$s
  done &&
  cp client-root-ca.crt sae-*.crt sae-*.key /work/
"
```

Upload `client-root-ca.crt` at **API → Upload Client CA Certificate**. The SAE
keys stay local.

For TC-04 you also need `rogue-sae-1`, signed by a second CA that is **never**
uploaded — see the report, section 5.

### 3. Run

```bash
docker run --rm -v "$(pwd):/work" -w /work python:3.12-slim \
  python src/qukaydee_etsi014.py <account_id>
```

Windows / Git Bash: prefix with `MSYS_NO_PATHCONV=1`.

Each script writes TLS session secrets to `qukaydee-keys.log`. Point Wireshark
at it under **Preferences → Protocols → TLS → (Pre)-Master-Secret log
filename** to decrypt the captures.

> The client runs in a container because the Windows and Git Bash builds of
> `curl` link against Schannel, which does not implement TLS key logging.
> CPython bundles OpenSSL, so this removes the host TLS stack from the picture.

---

## Layout

```
qkd-etsi014-poc/
├── docs/
│   ├── qkd-etsi014-report.pdf         the report
│   └── img/                           figures and Wireshark screenshots
├── src/
│   ├── qukaydee_etsi014.py            TC-01, TC-02, TC-03, TC-05
│   ├── tc04_identity.py               TC-04
│   ├── tc06_failure_conditions.py     TC-06
│   ├── tc07_connection_reuse.py       TC-07
│   ├── tc08_exhaustion.py             TC-08
│   ├── tc09_post_extensions.py        TC-09
│   └── tc10_multicast.py              TC-10
├── captures/
│   ├── *.pcapng                       packet captures backing every figure
│   └── qukaydee-keys.log              TLS session keys for the above
└── .gitignore
```

The scripts use the Python standard library only — no `pip install`.

**On the key log.** It is committed deliberately, so that the captures can be
decrypted and the claims in the report verified independently rather than taken
from screenshots. The sessions are closed, the account is a test account, and
the platform's keys are not cryptographically secure. This would not be
appropriate for a capture of production traffic.

---

## Companion

The same wire-level method applied to the other answer to the quantum threat:
**[pqc-tls13-oqs-poc](https://github.com/Rodolphe21/pqc-tls13-oqs-poc)** —
post-quantum TLS 1.3 with liboqs / oqs-provider, including a full
X25519MLKEM768 hybrid handshake and ML-DSA certificate fragmentation.

One instrument, two technologies, and a question neither datasheet answers:
what did the two sides actually agree on?

---

## References

- **ETSI GS QKD 014** — Protocol and data format of REST-based key delivery API
- **ETSI GS QKD 004** — Application interface (session-oriented)
- **ETSI GS QKD 015** — Control interface for SDN
- **ETSI GS QKD 018** — Orchestration interface for SDN
- **ETSI GS QKD 020** — Protocol and data format of REST-based Interoperable
  Key Management System API (published June 2026)
- OpenAPI descriptions: [forge.etsi.org/rep/qkd](https://forge.etsi.org/rep/qkd)

---

## Acknowledgement

This study was possible because QuKayDee provides a hosted, freely accessible
ETSI GS QKD 014 endpoint with a complete topology, certificate handling and
clear documentation. It was used strictly within the scope it declares. The
findings concern the specification and the ecosystem around it, not the
platform.
