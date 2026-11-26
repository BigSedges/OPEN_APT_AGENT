# Retrieval comparison (Silver, public evaluation summary)

This document summarizes a retrieval comparison run on a frozen public
knowledge corpus and a frozen set of 60 questions. It is a **public, compact
summary**. The corpus, indexes, model, and experiment artifacts are external
assets and are not distributed with this package.

- Comparison unit: **AiSOC PostgreSQL FTS component** vs the local RAG
  implementation.
- Main scope: **3,403-pair historical extension Silver pool**.
- Sensitivity scope: **2,197-pair four-way Q-anchor Top-20 union**.
- Labels: **Silver / LLM-as-a-judge**, not human Gold.
- Recall: candidate-pool estimate, not whole-corpus recall.
- nDCG: graded 0/1/2; it includes rel1 and must not be read as rel2 hit rate.
- AiSOC latency was not measured in the current environment.

## 49-question confirmatory subset

Recall and MRR use rel2; nDCG uses 0/1/2. Of 49 questions, 38 have a rel2
positive. Recall macro denominator is **38**; MRR and graded nDCG denominator
is **49**.

### 3,403 historical extension pool (main)

| Method | R@20 | MRR@10 | nDCG@20 | Empty |
|---|---:|---:|---:|---:|
| AiSOC PostgreSQL FTS component | .6065 | .5867 | .3512 | 13/49 |
| BM25 | .8249 | .6395 | .6047 | 0/49 |
| Dense | .9192 | **.7092** | .6459 | 0/49 |
| Hybrid | **.9624** | .6635 | **.6665** | 0/49 |

### 2,197 four-way union (sensitivity)

| Method | R@20 | MRR@10 | nDCG@20 |
|---|---:|---:|---:|
| AiSOC PostgreSQL FTS component | .6250 | .5867 | .3867 |
| BM25 | .8421 | .6395 | .6597 |
| Dense | .9408 | **.7092** | .7029 |
| Hybrid | **.9846** | .6635 | **.7245** |

Dense−Hybrid differences are directionally stable across both pools: Dense has
higher MRR; Hybrid has higher R@20/nDCG. The differences are small, so the
result does not establish a universal winner. Dense remains the default; BM25
and Hybrid remain configurable.

## 60-question exploratory set

| Method | R@20 | MRR@10 | nDCG@20 | Empty |
|---|---:|---:|---:|---:|
| AiSOC PostgreSQL FTS component | .5400 | .5292 | .3207 | 17/60 |
| BM25 | .8017 | .6306 | .5967 | 0/60 |
| Dense | .9240 | .7069 | .6314 | 0/60 |
| Hybrid | .9590 | .6692 | .6512 | 0/60 |

## Metric interpretation

- rel2 Recall/P/Hit/MRR treat zero-rel2 questions differently: Recall returns
  `None` and is skipped; P/Hit/MRR are 0 over the full 49/60 denominator.
- Graded nDCG uses `gain=2^grade−1` and includes all positive grades (rel1 and
  rel2) in IDCG. Of the 11 zero-rel2 questions in the 49 set, 7 are rel1-only
  and 4 have no positive grade; rel1-only questions can have non-zero nDCG.
- See the wheel/source `rag/evaluation.py` and the external experiment
  artifacts for the exact implementation.

## Scope

This is a comparison of an **AiSOC PostgreSQL FTS component**, not the complete
AiSOC product. The corpus is public-source knowledge; candidate pools are
frozen experiment artifacts. The results do not establish whole-corpus recall,
human Gold, or production performance.
