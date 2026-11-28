# LangGraph 调查工具接入规范 v1.0

本规范供两方使用。**工具作者**交付一份 `tool.json` 和一个可运行的程序。**Agent 作者**用适配器把这份清单注册为 LangGraph 工具，模型即可按清单中的名称和参数发起调用。工具可以用 Python、Go、Rust 等语言编写。现有二进制若使用专有参数或输出格式，可随包提供一个薄包装脚本负责翻译。

v1 面向本地、只读的调查任务，例如查询一条记录、扫描一批日志或检索调查手册。约定一次调用启动一个进程，通过标准输入输出交换一对 JSON 对象。以下为本项目的应用层协议，LangGraph 接入使用官方 `StructuredTool` 和 `ToolNode`。[LangGraph 工具执行](https://docs.langchain.com/oss/python/langchain/tools) · [图编排示例](https://docs.langchain.com/oss/python/langgraph/quickstart)

## 1　工具作者交付什么

| 交付项 | 要求 |
| --- | --- |
| 工具清单 | UTF-8 编码的 `tool.json`，声明名称、版本、启动方式、输入输出 Schema、超时和依赖资源。每个清单对应一个可调用能力。 |
| 可执行入口 | 脚本交付源文件和运行依赖。原生程序交付目标平台的可执行文件，或源码、构建命令及运行要求。程序读取一次 stdin，到 EOF 开始处理，写出一次响应并退出。 |
| 资源说明 | 给每项逻辑资源写明格式和所需字段。示例的 `records` 是 UTF-8 JSONL，每行含字符串 `physical_record_id`、`host`、`source_type`，物理 ID 在该案内唯一。宿主提供路径。 |
| 联调样例 | 至少提供可复现的成功、无匹配和失败情形，注明期望的响应。随附示例包另含 LangGraph 适配器与不依赖模型密钥的冒烟测试。 |

## 2　工具清单

下面是可直接使用的脚本清单。Go 版使用相同工具名和 Schema，只将 `argv` 改为 `["./lookup-record"]`。两份示例清单代表同一能力的两种实现，单个 Agent 注册其中一份。

```json
{
  "protocol_version": "1.0",
  "name": "lookup_record",
  "tool_version": "1.0.0",
  "description": "按本案物理 ID 查询记录的主机和来源；找不到时返回空记录。",
  "argv": [
    "{python}",
    "worker.py"
  ],
  "timeout_ms": 5000,
  "resources": [
    "records"
  ],
  "input_schema": {
    "type": "object",
    "properties": {
      "physical_id": {
        "type": "string",
        "minLength": 1,
        "description": "本案的物理记录 ID"
      }
    },
    "required": [
      "physical_id"
    ],
    "additionalProperties": false
  },
  "output_schema": {
    "type": "object",
    "properties": {
      "record": {
        "oneOf": [
          {
            "type": "null"
          },
          {
            "type": "object",
            "properties": {
              "host": {
                "type": "string"
              },
              "source_type": {
                "type": "string"
              }
            },
            "required": [
              "host",
              "source_type"
            ],
            "additionalProperties": false
          }
        ]
      }
    },
    "required": [
      "record"
    ],
    "additionalProperties": false
  }
}
```

| 字段 | 解释 |
| --- | --- |
| `protocol_version` / `tool_version` | 前者固定为字符串 `1.0`；后者标识该工具实现的非空版本。宿主在运行时固定清单和可执行文件版本。工具参数或业务返回发生不兼容变更时发布新主版本。 |
| `name` / `description` | 名称满足 `[a-z][a-z0-9_]{0,63}`，在注册给同一 Agent 的工具中唯一。描述说明用途和何时选用，供模型选工具。 |
| `argv` | 非空字符串数组，来自宿主安装的清单。工作目录为清单所在目录。`{python}` 只在第一项表示宿主当前 Python 解释器。带路径分隔符的相对程序路径以清单目录解析，裸程序名从宿主 PATH 查找。参数按数组传递，启动时使用 `shell=False`。 |
| `timeout_ms` | 正整数，单位毫秒。宿主分别管理单次进程超时与整个调查预算。参考适配器对直接启动的进程执行超时回收；会启动后代进程的包装器须另行管理其生命周期。 |
| `resources` | 本工具需要的逻辑资源名数组，允许为空。注册方为当前案件绑定已经存在的只读文件或目录，进程收到其绝对路径。资源文件读取属于已安装程序的权限，工具所在账户的操作系统权限由部署方管理。 |
| `input_schema` | 描述公开业务参数的 JSON Schema，顶层为 object，设置 `additionalProperties: false`。所有必填参数列入 `required`。保留名为 `runtime`、`config`、`context`、`argv`、`request_id`、`resources`。 |
| `output_schema` | 仅描述成功响应中的 `data` 对象。输入与输出均按 JSON Schema Draft 2020-12 校验；面向模型的输入 Schema 还应兼容所用模型供应商支持的子集。 |

## 3　进程协议

stdin 和 stdout 均为 UTF-8，使用标准 JSON，不含 BOM。一次调用恰好一个请求、一个响应，可有结尾换行。进度、调试和诊断信息写 stderr。参考宿主接受最多 1 MiB 的 stdout 响应；大结果由工具通过业务参数分页或按批处理，示例适配器在进程结束后校验返回大小。

### 请求

```json
{
  "protocol_version": "1.0",
  "request_id": "req-example-01",
  "tool": "lookup_record",
  "tool_version": "1.0.0",
  "context": {
    "case_id": "demo",
    "run_id": "run-1",
    "resources": {"records": "/work/case-demo/records.jsonl"}
  },
  "arguments": {"physical_id": "pr-demo-1"}
}
```

模型只填写 `arguments`。工具名和版本取自已注册清单。宿主为每次进程尝试生成唯一 `request_id`，将案件、运行和已授权资源注入 `context`。同一工具可能同时服务多个调用，程序按本请求处理数据，并以原值回传 `request_id`。示例中的路径和 ID 均是联调数据。

### 成功与无匹配

```json
{
  "protocol_version": "1.0",
  "request_id": "req-example-01",
  "ok": true,
  "data": {"record": {"host": "H1", "source_type": "sysmon"}},
  "evidence_ids": ["pr-demo-1"]
}
```

成功响应固定为上例五个顶层字段。`evidence_ids` 为无重复的非空字符串数组，数组本身允许为空。案件工具应返回本案可回查的物理记录 ID。内部事件 ID 由工具或适配层映射为物理 ID。RAG 工具把文档 ID 和片段定位放在自己的 `data` 内，只有知识引用时返回 `evidence_ids: []`。工具返回的记录仍需调查层判定和校验，最终比赛输出由导出器生成。

查询成功但没有匹配时，保持 `ok: true`。例如本工具返回 `data: {"record": null}` 和 `evidence_ids: []`。Sigma 扫描工具可以自行定义 `data.hits` 和 `data.coverage`，使调用方能区分已扫描但零命中、跳过的规则及部分扫描。

### 失败与退出码

```json
{
  "protocol_version": "1.0",
  "request_id": "req-example-01",
  "ok": false,
  "error": {"code": "DATA_ERROR", "message": "Invalid records resource.", "retryable": false}
}
```

业务失败固定为上例四个顶层字段。`error` 内含非空字符串 `code`、`message` 及布尔值 `retryable`。能生成有效成功或失败响应时，进程退出码均为 0。请求本身无法解析、程序崩溃或没有可返回的协议响应时，使用非零退出码。宿主优先检查超时与退出码，再校验 stdout。`retryable` 是给调查调度器的建议，参考适配器每次调用只执行一次。

| 错误码 | 产生方 | 调用方处理 |
| --- | --- | --- |
| `INVALID_ARGUMENT` | 宿主 | 模型业务参数不符合 Schema。修正参数后可发起新调用。 |
| `DATA_ERROR` | 示例工具 | 已收到有效请求，但资源内容无法读取或解析。其他工具应声明自己的业务错误码。 |
| `START_ERROR` / `PROCESS_EXIT` | 宿主 | 启动或访问进程失败，或进程以非零状态退出。保留诊断，检查部署及 stderr。 |
| `TIMEOUT` | 宿主 | 单次调用超时。预算允许时调度器可缩小查询范围再试。 |
| `BAD_RESPONSE` / `OUTPUT_LIMIT` | 宿主 | 回包不是规定的 JSON、版本或请求 ID 不符、字段或 Schema 错误、证据重复，或超出输出上限。 |
| `OUT_OF_SCOPE` | 宿主 | 证据 ID 不属于绑定案件，整次结果不进入证据集合。 |

## 4　Agent 作者如何接 LangGraph

`langgraph_adapter.py` 中的 `build_tool` 读取清单、绑定案件、校验输入并启动程序。它把成功或失败包装成可供 `ToolNode` 处理的 LangChain 工具结果。按案件和角色绑定工具实例，在同一案件内可复用。注册给模型和注册给执行节点的工具清单应一致。

```python
from pathlib import Path
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph_adapter import build_tool

root = Path("tool-package").resolve()
lookup = build_tool(
    root / "tool.json",
    case_id="demo",
    run_id="run-1",
    resources={"records": root / "records.jsonl"},
    valid_ids={"pr-demo-1"},  # 实际项目从本场景索引加载
)

def build_agent(chat_model):
    tools = [lookup]
    model = chat_model.bind_tools(tools)

    def agent(state):
        return {"messages": [model.invoke(state["messages"])]}

    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent)
    graph.add_node("tools", ToolNode(tools))
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", tools_condition, {"tools": "tools", "__end__": END})
    graph.add_edge("tools", "agent")
    return graph.compile()
```

`chat_model` 由接入方提供，需支持工具调用。图中模型发出 `AIMessage.tool_calls`，`ToolNode` 选择同名工具并返回 `ToolMessage`。每条工具消息通过 `tool_call_id` 关联模型请求；`ToolMessage.content` 是 JSON 字符串，解析后可得到进程层 `request_id`。`status="success"` 表示协议成功，`status="error"` 表示调用失败。并行调用按 ID 配对，不依赖返回顺序。

在共享黑板架构中，取证工具只返回资料或证据。宿主把任务、两类调用 ID、工具版本、资源快照和查询结果记入账本，经 Verifier 核验后再合并。图的预算、是否重试、是否采纳发现均由调用方控制。

## 5　最小联调与交付验收

在随附示例包的根目录使用 Python 3.12 虚拟环境，安装 `requirements.txt`。验收命令以 Linux 或 WSL 为例。脚本和原生实现共用查询样本、适配器和 LangGraph 测试。

```sh
python -m pip install -r requirements.txt
python smoke.py
go build -o lookup-record worker.go
python smoke.py tool.native.json
```

前两行即可验证脚本实现。测试原生实现时需要 Go 1.18 或更高版本。Windows 原生构建可将输出名和相应清单中的启动名改为 `lookup-record.exe`。工具作者可以只发目标平台二进制，由接入方直接注册。

| 用例 | 应观察到的结果 |
| --- | --- |
| 查询 `pr-demo-1` | 图返回成功工具消息，业务数据为 H1 和 sysmon，证据引用为该物理 ID。 |
| 查询 `absent` | 图返回成功工具消息，`record=null`，证据为空。 |
| 将 `physical_id` 传为整数 | 参数校验报 `INVALID_ARGUMENT`，进程不启动。 |
| 将有效记录集绑定为空集，再查询样本中的 ID | 工具回包被宿主拒绝，工具消息带 `OUT_OF_SCOPE`。 |

这四项用例在 `smoke.py` 中直接向图注入工具调用消息，经过真实 `ToolNode`，可以在没有模型密钥的环境中运行。接入自研工具时，还应验证进程超时、非零退出、意外打印到 stdout、响应 ID 不一致以及业务输出不符合 Schema 时的行为。

## 6　可以直接交给开发 Agent 的任务说明

> 请按本规范实现一个名为 **〈工具名〉** 的只读工具，其职责是 **〈一句话能力〉**。它接收 **〈业务参数〉**，读取宿主绑定的 **〈资源名与格式〉**，返回 **〈业务结果与无匹配语义〉**。交付 `tool.json`、脚本或原生程序、依赖或构建说明、一份最小样本，以及经过 LangGraph ToolNode 的测试。复用标准请求、成功响应和失败响应。涉及案件证据时使用原始物理记录 ID；只返回知识资料时将文档引用放入 `data`。列出实际测试的平台、版本及测试结果。

