

# Threshold Policy-based Chameleon Hash (TPCH)

We present an implementation of a **Threshold Policy-based Chameleon Hash (TPCH)**, built upon our RSA-based **t-out-of-n Threshold Chameleon Hash (TCH)** construction. TPCH extends the Policy-based Chameleon Hash (PCH) proposed at NDSS 2019 by introducing decentralized authorization and fine-grained redaction control without exposing the trapdoor. Additionally, we provide a policy-based chameleon hash (PCH) in NDSS19.

TPCH integrates **threshold cryptography** and **ciphertext-policy attribute-based encryption (CP-ABE)** to achieve secure, auditable, and one-time rewriting authorization in permissioned blockchains. It serves as the core cryptographic primitive for our **Transaction-level Redactable Blockchain (TPRB)** framework, enabling flexible yet verifiable data modification under distributed trust.

---

# Core Components of TPCH

We implement the following core algorithms:

* **TCH.Setup / TCH.KGen / TCH.Hash / TCH.Combine** — RSA-based threshold chameleon hash generation and adaptation
* **TPCH.Hash / TPCH.PAdapt / TPCH.Adapt** — Policy-based extension with CP-ABE encryption for fine-grained control

TPCH is designed upon:

* Threshold RSA and secret sharing over the integers
* Ciphertext-policy attribute-based encryption (CP-ABE)
* Non-interactive zero-knowledge proof for correctness verification

---

# Publication

This work is featured in our **IEEE TDSC** paper:
**"Redactable Blockchain Supporting Rewriting Authorization without Trapdoor Exposure"**
[Redactable Blockchain Supporting Rewriting Authorization without Trapdoor Exposure.](https://doi.org/10.1109/TDSC.2025.3557414)

Key features:

* **Authorization without trapdoor exposure** — Enables secure redaction without revealing secret keys
* **Fine-grained control** — Attribute policies define who can modify which transactions
* **Decentralized threshold management** — Trapdoor is distributed among multiple authorities
* **Transaction-level rewriting** — Supports efficient and auditable data modification

Potential applications include **redactable blockchains**, **regulatory-compliant ledgers**, and **secure data governance systems**.

---

# References

[Policy-based Chameleon Hashes and Applications to Blockchain Redaction.](https://www.ndss-symposium.org/ndss-paper/policy-based-chameleon-hashes-and-applications-to-blockchain-redaction/) Derler *et al.*, NDSS 2019
[Redactable Blockchain Supporting Rewriting Authorization without Trapdoor Exposure.](https://doi.org/10.1109/TDSC.2025.3557414) Wei Wang *et al.*, IEEE TDSC 2025


