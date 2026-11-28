# OPEN_APT_AGENT

面向 APT 防守场景的确定性优先、多 Agent 协作日志调查与 Sigma 规则/映射维护管线，基于 Python `>=3.12` 与 `uv` 管理。

## 架构概览

- **`src/apt_agent/`**：核心调查与规则维护包（配置加载、领域模型、异常契约、原始证据库与归一化、多检测引擎适配、权限受控工具注册表与 RAG 服务、黑板合并/核验/排序、维护流水线与标准分析入口）。
- **`packages/apt-rag/`**：独立检索包，内含 5,440 个公开知识片段（`public_kb/chunks.jsonl.gz`）、`RagClient`、CLI 及 LangGraph v1 外部工具 `search_knowledge`。见 [apt-rag 使用说明](packages/apt-rag/README.md) 与 [LangGraph 工具接入指南](packages/apt-rag/tools/langgraph_rag/README.md)。
- **`script/log_convert/`**：面向 6 类日志格式（16 种细分子类型）与 4 类检测引擎（Zircolite、Hayabusa、RSigma、Chainsaw）的确定性转换脚本与引擎配置。见 [log_convert 说明](script/log_convert/README.md) 与 [日志类型参考](LOG_TYPE.md)。

## 环境准备（`uv` + Python `>=3.12`）

如 `uv` 位于 `~/.local/bin`，先将其加入 `PATH`：

```sh
export PATH="$HOME/.local/bin:$PATH"
uv sync
```

在离线环境中可使用：

```sh
uv sync --offline
```

常用基础检查命令：

```sh
# 运行单元测试
uv run pytest

# 运行 LangGraph v1 search_knowledge 冒烟测试
uv run python -B packages/apt-rag/tools/langgraph_rag/smoke.py

# 使用公开知识库执行 BM25 检索
uv run python packages/apt-rag/search_public.py "Sysmon process creation" --top-k 2 --json
```

## 配置与 LLM 接入

所有本地检测引擎路径、规则集目录、RAG 资产、预算参数和 LLM 凭据均通过配置与环境变量注入，不写入源码：

1. **YAML 配置模板**：
   - 通用可移植模板：[`config/default.example.yaml`](config/default.example.yaml)
   - 本地引擎绑定模板：[`config/local.example.yaml`](config/local.example.yaml)（复制为本地未跟踪文件如 `config/local.yaml` 后填写各引擎路径、Takajo `working_dir`、Hayabusa `rules_dir`/`config_path` 等）。
2. **环境变量模板**：
   - 参考 [`.env.example`](.env.example)，支持 `APT_AGENT_CONFIG`、`APT_AGENT_<SECTION>__<FIELD>`（如 `APT_AGENT_LLM__API_KEY`、`APT_AGENT_ENGINES__ZIRCOLITE__BIN_PATH`）、常用扁平别名（如 `APT_AGENT_LLM_MODEL`、`APT_AGENT_RAG_MODE`）以及标准 `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `OPENAI_MODEL`。
3. **加载优先级**：
   `overrides` > `APT_AGENT_*` 环境变量 > `OPENAI_*` 环境变量 > YAML 配置文件 > `AppConfig` 默认值。
4. **运行模式**：
   - 未配置 LLM（`llm.enabled: false` 或缺少模型/凭据）时，系统支持纯离线确定性回退模式。
   - 填写完成 `llm` 配置（`enabled: true`、`base_url`、`api_key`、`model`）后即可启用 OpenAI 兼容 LLM 规划与推理。

## 外部标准分析入口契约

主入口 `apt_agent.analyze_records(records)` 接收单遍消费的 `Iterator[tuple[str, dict[str, Any]]]`（`(physical_record_id, payload)`），返回严格满足接口规范的 JSON 兼容字典：

```json
{
  "physical_id_set": ["pr-001", "pr-002"],
  "ta_physical_ids": {
    "TA0002": ["pr-001"]
  }
}
```

## 仓库文档索引

- [日志类型参考](LOG_TYPE.md)
- [Sigma 多 Agent 日志调查系统设计](docs/Sigma多Agent日志调查系统设计.md)
- [Sigma 多 Agent 调查系统接口规范](docs/Sigma多Agent调查系统接口规范.md)
- [LangGraph 外部工具接入规范 v1](docs/LangGraph外部工具接入规范-v1.md)
- [独立检索包评估对比](packages/apt-rag/docs/retrieval_comparison.md)
