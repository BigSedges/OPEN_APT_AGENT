# OPEN_APT_AGENT

面向 APT 防守场景的日志分析项目。仓库包含日志分析接口和可独立运行的 RAG 检索包。日志分析流水线仍处于接口阶段。

## RAG 知识库快速体验

使用带 RAG 文件的 checkout 和 Python 3.10+。如果当前 checkout 还没有 `packages/apt-rag/`，先克隆 [PR #2 的分支](https://github.com/BigSedges/OPEN_APT_AGENT/pull/2)：

```sh
git clone --branch release/apt-rag-0.1.0 https://github.com/BigSedges/OPEN_APT_AGENT.git
cd OPEN_APT_AGENT
```

在仓库根目录运行：

```sh
python packages/apt-rag/search_public.py "Sysmon process creation" --top-k 3
```

首次搜索无需安装依赖或下载模型。随仓库提供 5,440 个公开片段，并支持输入本地全量资产。见 [apt-rag 使用说明](packages/apt-rag/README.md)。

## 仓库导航

- [日志分析接口](apt_agent/)：事件模型、日志类型与解析、初筛、关联、检索、分析和编排协议。根目录项目声明 Python 3.9+。
- [日志类型参考](LOG_TYPE.md)：主机、应用和网络日志分类。
- [独立检索包](packages/apt-rag/)：Python 3.10+。包含离线查询、Python API、命令行和公开语料快照。
- [当前检索评估](packages/apt-rag/docs/retrieval_comparison.md)：完整 v2 语料上的 Phase 5B 比较与指标口径。
- [早期实验归档](https://github.com/BigSedges/OPEN_APT_AGENT/tree/codex/public-rag-results/experiment-results/public-rag-2026-11-25)：2026-11-25 先导指标、配置和逐题结果，留在独立归档分支。

## 开发状态

日志分析入口由各阶段接口继续实现。RAG 可以独立调用。GitHub 上的 RAG 历史评估、当前公开快照和本地完整索引使用不同的资产范围，详细对应关系见 [仓库与产物说明](docs/repository-guide.md)。
