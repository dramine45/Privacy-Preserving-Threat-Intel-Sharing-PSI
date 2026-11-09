# Privacy-Preserving Threat-Intelligence Sharing

**Private Set Intersection (PSI) for SOC/CSIRT teams using homomorphic encryption, post-quantum lattice cryptography, zero-knowledge proofs and STIX 2.1 interoperability.**

> Course project: *Advanced Cryptography and Privacy Engineering* — ICCN INE3, INPT — Pr. Ch. HANIN — 2026-2027
>
> 📓 The notebook (`PSI_Threat_Intel_Sharing_FR_execute_graphes.ipynb`) and its comments are written in **French**.

---

## Problem

Several organizations (bank, telecom, hospital, government agency…) each hold a private list of **Indicators of Compromise (IOCs)**: IP addresses, domains, URLs, file hashes. They want to learn **which IOCs they have in common**, which signals a campaign hitting several sectors, **without revealing the rest of their lists**. An IOC list exposes what an organization was attacked by, what it monitors, and sometimes who its customers are.

This project implements and compares several cryptographic answers to that problem, entirely **from scratch in pure Python + NumPy**, and runs them on **real public threat-intelligence feeds**.

## What's implemented

| # | Component | Course topic |
|---|-----------|--------------|
| 1 | IOC normalization (refanging, typed prefixes) and loading of **real public feeds**, where each feed plays the role of one organization | – |
| 2 | **Baseline**: naive hash sharing, broken by a dictionary attack | Hash functions, assumptions |
| 3 | **Paillier polynomial PSI** (additively homomorphic encryption) with **binning** | Homomorphic encryption |
| 4 | **LWE / Bloom-filter PSI** (post-quantum, lattice-based, *toy parameters*) | LWE + HE |
| 5 | **Zero-knowledge proof** (batched Chaum–Pedersen DLEQ) over a minimal DH-PSI transcript, in a safe-prime group | DDH/CDH + ZK |
| 6 | **STIX 2.1 export** of the intersections found by Paillier and LWE (SIEM/TIP ready) | – |
| 7 | Summary of automated checks, measured costs and lessons learned | – |
| 8 | **Visualizations** (5 figures) | – |

## Pipeline

```text
real public feeds ──normalize_ioc──▶ orgs {org: {ioc: metadata}} ──▶ real pair (X, Y)
                                                                      ├─▶ Paillier-PSI (HE)    ──┐
                                                                      ├─▶ LWE-Bloom-PSI (PQ)   ──┼─▶ STIX 2.1 bundle ─▶ SIEM / TIP
                                                                      └─▶ DH transcript ─▶ DLEQ proof (server honesty)
```

## Threat model

- **Paillier-PSI and LWE-PSI**: participants are *semi-honest* (honest-but-curious). They follow the protocol but analyze the transcript.
- **Section 4** considers a **quantum** adversary (LWE instead of factoring / discrete log).
- **Section 5** considers a **malicious server** (zero-knowledge proof of key consistency).
- A secure channel (TLS) is assumed; the project studies the *cryptographic* leakage on top of it.
- Ideal functionality: `F_PSI(X, Y) = (X ∩ Y, |X| and |Y| revealed)`. Each protocol is compared against this ideal.

## Data sources

Real, current IOCs are downloaded from public feeds and cached in `feed_cache/` so runs are reproducible (delete the folder to refresh).

- **Default feeds:** IPsum, CINS Army, Blocklist.de, Emerging Threats (compromised IPs), Phishing Database (domains and URLs)
- **Optional feeds (`OPTIONAL_FEEDS`):** abuse.ch Feodo / URLhaus / MalwareBazaar, OpenPhish, Neo23x0 C2 and hash lists
- **Your own data:** add a local list via `LOCAL_FILES`

> **Honest framing:** since these feeds are public, the "privacy" here is *simulated*. In a real deployment each party feeds the **same code** with its own *private* telemetry (SIEM/EDR/firewall hits). The protocols do not change.

Feeds are sampled with a coordinated strategy (capped at `MAX_PER_ORG` IOCs per organization) so that true overlaps between feeds survive the cap. The ground-truth intersection is therefore known exactly.

## Sample results

Measured on the demo pair `Phishing-domains` vs `Phishing-links` (100 IOCs per side, 25 shared), snapshot of 2026-10-28:

| Result | Value |
|--------|-------|
| Dictionary attack on hashed IOCs (a real /16) | 20/20 IOCs recovered in 0.13 s on one CPU core |
| Paillier-PSI, 1 bin | 11.8 s, 50 KiB |
| Paillier-PSI, 12 bins | 6.5 s, 67 KiB, server-side ×3.8 faster with binning |
| LWE/Bloom-PSI (toy) | 0.01 s, 116 KiB, 25/25 found, 0 false positives |
| Batched DLEQ proof (100 elements) | ~0.8 KiB (constant size), verified in 0.48 s |
| Individual DLEQ proofs (100 elements) | ~81 KiB, i.e. 100× larger than the batched proof |
| STIX 2.1 bundle | 25 indicators + 1 identity, validated and round-tripped |
| Automated checks | **24 / 24 pass** |

### Protocol comparison

| | Paillier polynomial PSI | LWE / Bloom PSI (this notebook) | Production lattice PSI (FHE, e.g. APSI) |
|---|---|---|---|
| Hardness assumption | Composite residuosity | **LWE** | **(R)LWE** |
| Quantum-resistant | ❌ (Shor) | ✅ | ✅ |
| Rounds | 2 | 3 | 2 |
| Extra leakage | none beyond ∩ and sizes | partial Bloom counts + false positives | none |
| Exact result | ✅ | ❌ (Bloom FPs) | ✅ |
| Best for | learning HE, small sets | post-quantum readiness study | post-quantum + large sets |

## Getting started

### Requirements

- Python 3.10+ (developed on 3.12)
- `numpy`, `pandas`, `mpmath`, `matplotlib`
- Optional: `stix2` (used to cross-check the exported bundle)
- Internet access on the first run to download the feeds

The first cell installs missing packages automatically. Or install them manually:

```bash
pip install numpy pandas mpmath matplotlib stix2 jupyter
```

### Run

```bash
git clone <your-repo-url>
cd <your-repo>
jupyter notebook PSI_Threat_Intel_Sharing_FR_execute_graphes.ipynb
```

Then run all cells. With `FAST = True` (default) everything finishes in a few minutes on a laptop.

### Configuration knobs

| Variable | Meaning | Default |
|----------|---------|---------|
| `FAST` | `False` = larger sets, several more minutes | `True` |
| `MAX_PER_ORG` | Cap on IOCs per organization | 300 (fast) / 1000 |
| `PSI_N` | Max IOCs per side for the toy-parameter protocols | 100 (fast) / 250 |
| `PAIR` | Force the two organizations used by the 2-party protocols, e.g. `("IPsum", "Blocklist.de")`; `None` = pair with the largest real overlap | `None` |
| `IPSUM_MIN_LISTS` | Keep IPsum IPs reported by at least this many lists | 3 |
| `OPTIONAL_FEEDS` / `LOCAL_FILES` | Enable extra feeds / add your own IOC files | – |

## Outputs

- `figures/`: 5 PNG figures generated during execution (all plotted values are measured at run time, nothing hard-coded)
  1. Dictionary-attack time against hashed IOCs
  2. Paillier-PSI: effect of binning on time and communication
  3. LWE/Bloom: partial-count leakage and false positives
  4. Batched vs. individual DLEQ proofs
  5. Summary of measured costs
- `psi_threat_intel_bundle.json`: STIX 2.1 bundle ready for a SIEM/TIP (MISP, OpenCTI, Sentinel…, e.g. via TAXII)
- `feed_cache/`: cached feed downloads

## Key takeaways

- **Hashing is not privacy.** IOCs have low entropy and are enumerable. PSI leaks exactly the ideal functionality: the intersection and the set sizes.
- **HE-based PSI** hides the server's whole set through homomorphic polynomial evaluation. Binning cuts server cost from `O(m·d)` to `O(m·L)`.
- **Lattice-based PSI** removes the quantum weakness of factoring / discrete-log constructions. The toy version exposes the engineering trade-offs: Bloom false positives, partial-count leakage, ciphertext expansion.
- **ZK proofs** stop a malicious server from using inconsistent keys, with constant-size proofs. But **no cryptography prevents input stuffing / enumeration** (e.g. submitting a whole /16 to probe the victim). Combine PSI with policy: set-size caps, probing budgets, signed inputs, cardinality-only mode for low-trust partners.
- **Interoperability:** results are exported as valid, deduplicated STIX 2.1 indicators (deterministic UUIDv5, so re-exports are idempotent) that record which protocol confirmed them.

## ⚠️ Security disclaimer

This is an **educational implementation**. Parameters are intentionally small to run quickly (1024-bit Paillier modulus, toy LWE parameters), and the code has not been audited. **Do not use it in production.** Use ≥ 3072-bit Paillier moduli and vetted libraries (SEAL, OpenFHE, APSI, libsodium…) for real deployments.

## Ideas for extension

1. Replace the Bloom filter with a real **RLWE/BFV** scheme (SEAL / TenSEAL / OpenFHE) for exact, batched PSI.
2. Use **elliptic curves** (e.g. Ristretto255) instead of the 2048-bit MODP group, for ~10× smaller messages and proofs.
3. Add a **post-quantum ZK** layer (lattice- or hash-based proofs) so Section 5 is also quantum-resistant.
4. Wrap the protocols and STIX export in a small **TAXII 2.1 HTTP service** with mutual TLS and signed inputs.

## References

- Meadows (1986), *A more efficient cryptographic matchmaking protocol*; Huberman–Franklin–Hogg (1999): commutative-blinding PSI (DH transcript)
- Paillier (1999), *Public-key cryptosystems based on composite degree residuosity classes*; Freedman–Nissim–Pinkas (2004), *Efficient private matching and set intersection*
- Regev (2005), *On lattices, learning with errors…*; NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
- Chen–Laine–Rindal (2017), *Fast private set intersection from homomorphic encryption*; Microsoft APSI
- Chaum–Pedersen (1992): DLEQ proofs; Fiat–Shamir (1986)
- RFC 3526 (MODP groups); STIX 2.1 / TAXII 2.1 (OASIS)

## License

Add your license here (e.g. MIT).
