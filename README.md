# TPCH
We present a t-out-of-n threshold chameleon hash (TCH) based on RSA and introduce a threshold policy-based chameleon hash (TPCH). Additionally, we provide a policy-based chameleon hash (PCH) in NDSS19.
This repository provides reference implementation and experimental scripts for the Threshold Policy-based Chameleon Hash (TPCH) and the corresponding Transaction-level Redactable Blockchain (TPRB) framework proposed in the paper.

This work is featured in our IEEE TDSC paper:
“Redactable Blockchain Supporting Rewriting Authorization without Trapdoor Exposure”
IEEE Transactions on Dependable and Secure Computing (TDSC), 2025
DOI: 10.1109/TDSC.2025.3557414
Overview
We present a t-out-of-n Threshold Chameleon Hash (TCH) based on RSA and further introduce the Threshold Policy-based Chameleon Hash (TPCH), which supports authorization without trapdoor exposure.
Compared to the Policy-based Chameleon Hash (PCH) from NDSS 2019, our TPCH achieves fine-grained rewriting control via ciphertext-policy attribute-based encryption (CP-ABE) and secure threshold management of long-term trapdoors.
Built upon TPCH, the TPRB protocol enables transaction-level, decentralized, one-time redactions with formal security proofs and efficient performance.
