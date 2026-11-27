# COPOD 与融合初筛工具（调查工具协议 v1.0）

交付两个独立能力，均为本地只读调查工具：

- `tools/copod/tool.json`：`rank_copod_candidates`，固定参考分布 COPOD。
- `tools/fusion/tool.json`：`rank_fused_candidates`，COPOD 与参考实体稀有度的等权 RRF60。

每个目录均有自己的清单和 `worker.py`；共享实现位于 `apt_agent/screening/`，部署时应保留仓库布局。工具一次启动一个进程，EOF 后读取一次 UTF-8 JSON 请求，返回一次 JSON 响应并退出。成功、空结果和可表达的业务失败退出码均为0；无法解析请求等情形非零退出。stdout 只用于协议，诊断用 stderr。

## 安装与联调

推荐 Python 3.11，Windows/Linux 均使用相同 Python 入口：

```sh
python -m venv .venv
# 激活虚拟环境后
python -m pip install -e ".[screening,langgraph-tools]" pytest
python tools/smoke.py
```

`tools/requirements-tested.txt` 保存实测环境的精确依赖版本。只需要进程工具、不接 LangGraph 时，可以仅安装 `.[screening]`。工具本体无需模型 API 密钥、不使用网络，也不调用其他外部模型。

此处复用的是历史统计流程，**不是外部预训练权重**。它会在每次调用的内存中从宿主绑定的独立参考数据估计分布、类别频率、均值/方差与偏度，不持久化模型，也不修改资源。这不满足“禁止一切本地拟合、只许外部权重”的实验模式。仅在调查方明确选择该统计方案时注册；不能把本工具包装成纯预训练推理。

## 宿主绑定资源

模型只能填写 `k`、`offset`、`limit`，不能指定路径、运行参数、参考案例或可执行程序。

`records`：当前案件的只读 UTF-8 JSONL 文件。每行：

```json
{"physical_record_id":"demo-1","host":"demo-host","source_type":"synthetic","categories":[1,1,1,1,1,1,1],"numbers":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"entity":"subject\u001fdemo-entity"}
```

- `physical_record_id`：案内唯一非空字符串，最大256字符，直接作为证据引用。
- `host`、`source_type`：字符串，记录采集范围和来源。预处理缺真实主机时使用明确的collector范围。
- `categories`：7个无符号64位整数。0表示缺失；其余为稳定 BLAKE2b 64位字段哈希。字段顺序为 event、outcome、actor_image、target_name、parent_image、context、text_shape。必须保留整数精度，不能经 JavaScript Number 等有损转换。
- `numbers`：16个有限数值，必须由 v1 预处理语义产生，不能直接拿任意数值替换。顺序见 `normalization.NUMERIC_COLUMNS`：文本长度、词数、最长词、数字比例、非字母数字比例、路径分隔符、长编码串、字段数、两端口、双向字节、时长、命令开关数、是否有文本/父进程。计数类使用原实现的log1p变换，其余比例/布尔保持原语义。
- `entity`：可选字符串，默认空。实体类型与原文标签以U+001F分隔，标签截断2048字符；优先主体映像+命令，其次文件/注册表目标，最后目的网络端点。空字符串不进入稀有度分支。
- `locator`：可选，为null或`{"filepath":"data/demo.jsonl","linenumber":1}`。它是回查位置，不作为可执行路径；位置按源格式为行/Event块/Bash命令组，从1开始。宿主Verifier回查前仍需检查路径范围。

`references`：独立参考案件的只读目录，每个 `*.jsonl` 为一个参考集合，行格式相同。所有文件按文件名排序；不得包含当前records文件。每个参考文件用seed=43+文件序号最多采样60,000条供COPOD拟合；实体稀有度统计全部参考记录。目录不能混入答案、历史分数或其他JSONL产物。至少需一个非空参考集合；不提供参考数据时明确失败，不偷偷用待调查案件拟合。

宿主必须冻结清单、代码和资源快照。同一资源快照下分页保持同一排序；每次分页都重新计算，不写共享缓存。资源格式和预处理属于本工具版本契约，标签或答案派生信息不得进入任何特征字段。

### 从原始日志生成资源（离线准备步骤）

```sh
python -m apt_agent.screening.prepare --scene /local/case --output /local/features/case.jsonl
```

输入为单场景目录，含中性定位索引 `Label_Index.json` 和 `data/`。支持既有ECAR/Zeek JSONL、Windows XML、syslog、Web访问日志和Bash历史，使用原始文件名对应的来源类型。仅读取索引及其定位的日志，不读取 `Label.json`。输出必须位于场景外，且不能覆盖已有文件。

这是宿主部署前运行的写入步骤，**不注册为Agent工具**。Agent调用的两个worker只读取已绑定的特征资源。若解析中断，删除不完整输出并重新准备，不把部分文件绑定到调查工具。敏感日志产生的特征和实体标签同样属于私有数据，必须存放在仓库外。

## 业务参数和结果

- `k`：总候选预算0–10000，默认5000；0返回成功空结果。
- `offset`：分页起点0–10000，默认0。
- `limit`：本页1–200条，默认100，控制1 MiB响应限制。

输出 `data.candidates` 保留全局rank、physical_record_id、score、copod_score、可空entity_score与可空locator；`evidence_ids` 仅包含本页ID，去重且属于绑定案件。

`coverage` 返回记录数、COPOD评分数、实体可评分数、候选池大小和参考记录数。`selected_count` 是总预算内的实际候选数；`next_offset=null` 表示没有下一页。记录集为空、k=0或页码超出已选范围都返回 `ok:true` 和空候选/证据。

算法明确区分：

1. 固定参考COPOD：只用参考数据构建类别稀有度、标准化与经验尾部分布，待查数据不更新这些统计。它使用COPOD尾部组合公式，**不等同原版PyOD查询批次参与经验分布的版本**。
2. 融合：分别取COPOD与实体稀有度前10000名，使用 `1/(60+rank)` 等权相加，合并后排序；并非按分数相加，不加入多样性D重排。
3. 固定同分顺序为seed=11产生的排列，依赖输入记录顺序；准备程序按索引源路径、记录位置确定顺序。不能把同分顺序解释为额外的恶意置信度。
4. 所有分数均不代表恶意概率，候选需由调查层和Verifier核验。

进程业务错误包括 `INVALID_REQUEST`、`DATA_ERROR`、`INTERNAL_ERROR`、`OUTPUT_LIMIT`。参数Schema的 `INVALID_ARGUMENT`、启动/退出/超时、非法回包和 `OUT_OF_SCOPE` 由适配器产生。没有自动重试或自动切换方法。

## 接入 LangGraph

```python
import json
from pathlib import Path
from langchain_core.messages import AIMessage
from langgraph.graph import START, END, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from apt_agent.screening.adapter import build_tool

root = Path.cwd()
resources = {"records": root / "tools/examples/records.jsonl",
             "references": root / "tools/examples/references"}
allowed = {json.loads(line)["physical_record_id"]
           for line in resources["records"].read_text(encoding="utf-8").splitlines()}
tools = [build_tool(root / "tools" / name / "tool.json",
                   case_id="demo", run_id="run-1",
                   resources=resources, valid_ids=allowed)
         for name in ["copod", "fusion"]]
graph = StateGraph(MessagesState)
graph.add_node("tools", ToolNode(tools))
graph.add_edge(START, "tools")
graph.add_edge("tools", END)
response = graph.compile().invoke({"messages": [AIMessage(content="", tool_calls=[{
    "id": "call-demo", "name": "rank_fused_candidates", "type": "tool_call",
    "args": {"k": 5, "limit": 2}}])]})
print(response["messages"][-1].content)
```

`ProtocolTool`继承官方StructuredTool，公开清单中的业务Schema；通过官方ToolNode产生关联原tool_call_id的ToolMessage，按回包ok设置success/error状态。支持同步/异步调用。模型绑定和ToolNode应使用同一tools列表。

适配器以argv数组和shell=False启动进程，工作目录为清单目录；校验Draft 2020-12、版本、request_id、顶层字段、重复证据与案内ID，响应上限1 MiB。有效失败回包会保留；错误不会成为正常证据。注册时可传 `diagnostics=本地回调` 接收有界stderr和request_id；不要把原始stderr直接发给模型或外部追踪服务。

这是已安装可信程序的应用协议，不是操作系统沙箱。宿主应只读挂载资源、隔离Label/历史分数和其他案件，禁用包含敏感事件的外部追踪，按case/role绑定实例并把工具版本、request_id、tool_call_id及资源快照记入本地账本。参考适配器只回收直接进程；本工具worker不会启动子进程。

## 验收和发布范围

测试不需要LLM密钥，直接向真实ToolNode注入合成AIMessage工具调用。覆盖两工具成功/分页/空结果、错误类型、资源错误、越界ID、超时、非零退出、stdout污染、request_id不符、输出Schema不符、重复证据与超限输出。

仓库只提供通用代码、清单、说明及显式合成demo数据。真实数据、标签、特征、参考统计、候选和本机诊断不属于发布包。实际平台、版本与结果见 `tools/VALIDATION.md`。
