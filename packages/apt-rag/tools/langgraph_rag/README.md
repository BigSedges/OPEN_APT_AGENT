# LangGraph 外部工具：search_knowledge

本目录实现《LangGraph 调查工具接入规范 v1.0》的只读知识检索能力。
`tool.json` 声明工具名、进程启动参数、逻辑资源、超时和 Draft 2020-12
输入/输出 Schema。`worker.py` 每次只处理一个 UTF-8 JSON 请求，等待 stdin
EOF 后运行。stdout 仅有一个 JSON 响应，诊断走 stderr。

请保留目录层级。worker 从上两级的 RAG 项目加载 `search_public.py` 或
现有 `apt_rag/` 和 `rag/`。既有 Python API 和命令行仍可独立使用。

## 绑定资源

注册时，宿主将 `resources.knowledge` 绑定到当前案件允许的**绝对文件路径**。
模型只能提供 `query`，可选 `top_k`（1–20，默认 5）和 `mode`（默认 `bm25`）。

| 资源 | 运行要求 | 检索模式 |
| --- | --- | --- |
| `sample_knowledge.jsonl`、公开 `chunks.jsonl.gz` 或本地 `chunks.jsonl` | Python 3.10+ 标准库 | 便携 BM25 |
| 现有 `configs/rag.yaml` | 原有 RAG 依赖、原始语料与索引 | 原始 BM25、Dense、Hybrid；后两者使用本地模型，配置须为离线 |

JSONL 每行一个对象，至少包括非空字符串 `chunk_id`、`document_id`、`text`。
可选 `source_url`、`source_version`、`author` 用于出处和署名。JSONL.GZ 是同一
格式的 gzip 压缩文件。输入是宿主提供的冻结知识快照。资源 URI 只做引用，
工具不会发起网络取证或读取比赛数据。

## 注册给 ToolNode

在以下目录运行示例，或把本目录加入宿主导入路径。一份清单注册一次：

```python
from pathlib import Path
from langgraph.prebuilt import ToolNode
from langgraph_adapter import build_tool

here = Path.cwd()  # 当前目录为 tools/langgraph_rag
knowledge = build_tool(
    here / "tool.json",
    case_id="demo",
    run_id="run-1",
    resources={"knowledge": here / "sample_knowledge.jsonl"},
)
tools = [knowledge]
node = ToolNode(tools)
# 使用模型时，chat_model.bind_tools(tools) 也接收同一组工具。
```

使用本地完整索引时，将示例文件换为本地 `configs/rag.yaml` 的绝对路径。
如果 worker 和数据位于不同的 RAG 项目根目录，配置中的 `project_root`
也要写成数据所在项目根的绝对路径。原有相对根路径语义保持不变。
`ToolMessage.content` 是 JSON 字符串，按 `tool_call_id` 关联模型调用，
按进程响应的 `request_id` 关联执行日志。调用者可以记录
`data.snapshot_id`、实际检索模式和降级警告。

## 业务响应与验收

- 命中时 `ok=true`。引用字段包含检索 ID、文档 ID、片段 ID、版本、
  定位、原文摘录和匹配原因。每段摘录最多 1,200 字符。
- 成功但无匹配时，`ok=true` 且 `data.refs=[]`。
- 这是知识工具。所有成功响应的 `evidence_ids=[]`。参考适配器即使收到
  宿主的案件证据 ID 集合，也会拒绝本工具夹带的任何物理证据 ID。
- 可解析的业务失败用 `ok=false`、进程退出码 0。业务错误包括
  `INVALID_ARGUMENT`、`DATA_ERROR`、`MODE_UNAVAILABLE`、
  `DEPENDENCY_MISSING`、`RETRIEVAL_ERROR`。无效进程信封或程序故障用非零退出码。
- 宿主限时 60 秒，单次 stdout 最大 1 MiB；worker 请求上限 32 KiB。
  宿主和调度器负责决定是否重试。Dense/Hybrid 按次启动进程和加载模型。

在宿主的独立环境中安装联调依赖并运行：

```sh
python -m pip install -r requirements-host.txt
python -B smoke.py
```

`smoke.py` 直接给真实 `ToolNode` 注入工具调用，无模型密钥。
`demo_event` 预期返回 `kb-demo-1`；`no-match-745xz` 预期无匹配；
损坏的 JSONL 预期返回 `DATA_ERROR`；`query=1` 预期由宿主拒绝。
测试也覆盖并行关联、超时、非零退出、额外 stdout、请求 ID 错误、
输出 Schema 错误、超限与知识工具夹带案件 ID。
