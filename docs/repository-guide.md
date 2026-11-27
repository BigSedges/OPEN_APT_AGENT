# 仓库与产物说明

## 分支

- `main` 是默认分支。查看已合并内容时从这里进入。
- `release/apt-rag-0.1.0` 提供独立的 RAG 源码、离线入口和公开语料，变更见 [PR #2](https://github.com/BigSedges/OPEN_APT_AGENT/pull/2)。
- `codex/public-rag-results` 保留 [2026-11-25 公开实验归档](https://github.com/BigSedges/OPEN_APT_AGENT/tree/codex/public-rag-results/experiment-results/public-rag-2026-11-25)。其中有开发题草稿、先导报告、逐题结果及清单。先导指标适用于当时的受控子集。
- `y3u1` 是日志类型工作分支，内容通过 [PR #1](https://github.com/BigSedges/OPEN_APT_AGENT/pull/1) 合入了主线。

## 根据用途选择入口

1. **离线搜索**：运行 [search_public.py](../packages/apt-rag/search_public.py)，使用仓库内的 [5,440 片段公开快照](../packages/apt-rag/public_kb/README.md)。无需安装 Python 依赖。
2. **集成到应用**：按 [RagClient 使用说明](../packages/apt-rag/README.md) 从源码安装，配置外部语料、索引和所选模式所需的模型。当前仓库没有提供预构建 wheel 的下载，安装记录中保留的是此前的本地构建验收结果。
3. **阅读 Phase 5B 结果**：见 [检索对照摘要](../packages/apt-rag/docs/retrieval_comparison.md)。该实验使用本地完整的 5,500 片段 v2 语料。3,403 对历史扩展 Silver 池是主口径，2,197 对四路 Q-anchor 并集用于敏感性分析。AiSOC 对照范围是 PostgreSQL FTS 组件。
4. **核验版本**：[公开快照清单](../packages/apt-rag/public_kb/manifest.json) 校验当前 Git 语料；[历史交付清单](../packages/apt-rag/docs/DELIVERY_MANIFEST.public.json) 记录 0.1.0 本地 wheel 验收时的文件哈希和完整评估资产信息。后者的 README 哈希对应最初交付版本。

公开数据的授权和署名按 [来源说明](../packages/apt-rag/public_kb/README.md) 管理。完整本地索引、模型权重、比赛数据和原始实验记录在仓库之外。仓库目前没有根级软件许可证。
