# RAG 检索

独立的 [apt-rag 包](../packages/apt-rag/README.md) 提供公开知识库、BM25 检索、Python API 和 LangGraph 外部工具。公开快照包含 5,440 个知识片段，可在仓库根目录离线试用。

```sh
uv run python packages/apt-rag/search_public.py "Sysmon process creation" --top-k 3
uv run python -B packages/apt-rag/tools/langgraph_rag/smoke.py
```

`RagService` 在案件内按角色、版本和快照过滤。Lead 用资料规划调查，Challenger 用历史资料寻找可复核的替代解释。检索结果保存为知识引用，本案证据由日志查询提供。

- [LangGraph 外部工具接入规范](LangGraph外部工具接入规范-v1.md)
- [search_knowledge 工具清单](../packages/apt-rag/tools/langgraph_rag/tool.json)
- [完整语料的评估和指标口径](../packages/apt-rag/docs/retrieval_comparison.md)
