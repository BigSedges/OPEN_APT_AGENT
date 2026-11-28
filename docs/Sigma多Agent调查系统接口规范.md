# Sigma 多 Agent 调查系统接口规范

本规范面向实现日志接入、Sigma 检测、知识检索、Agent 调查和比赛提交的开发者。对接 A 榜时，调查模块从一条物理记录出发，可以产生多个事件、命中和假设，最终提交的每个证据 ID 都要能还原到本场景 `Label_Index.json` 的键。

**对接边界。** 第 1、2 节描述当前 starter 的输入输出及本系统的导出约定。第 3 至 6 节定义拟实现的 Python 进程内接口，供各模块独立开发与联调。第 6 节提供比赛输出样例，第 7 节列出入口、评分器和内部模块各自的验收条件。

## 1　场景输入与读取

### 1.1　调用入口

`submission_agent/runner.py` 为每个场景调用一次：

```python
def analyze_records(records: Iterator[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    ...
```

| 位置 | 契约 |
| --- | --- |
| 调用方 | runner 发现并读取场景，将 `load_indexed_records(index_path, data_dir)` 的迭代器传给分析函数。当前工作副本在函数体内转调 `apt_tracer.pipeline.run_analyze_records(records)`。 |
| 输入元素 | 第一个值是索引中的 `physical_record_id`，第二个值是该条记录的正文对象。输入顺序来自索引的遍历顺序，分析时间线应使用解析出的事件时间。 |
| 消费方式 | 按一次遍历设计。多个引擎或 Agent 共用数据时，由接入层在首遍按物理 ID 建立本次运行的记录库，后续通过该库查询或重放。 |
| 返回 | 返回一个可 JSON 序列化的预测字典，字段见第 2 节。正常的无命中场景也返回这个结构。目录、JSON 文件和完成标记均由 runner 写入。 |
| 可见信息 | 函数签名只传记录流。runner 使用的场景名、文件路径与记录位置不会自动附加到每条记录。正文自身携带的同名字段须按原始日志语义解释。 |

**实现选项。** 使用原签名即可扫描正文并以物理 ID 回查。如果归一化必须知道文件名或精确来源，场景包装层可从当前索引建立只读的 `physical_record_id → Locator` 旁表，通过内部上下文提供给管线。只有记录流时将 `locator` 设为 `null`，来源无法可靠识别时记录覆盖缺口。每次调用创建独立案件上下文。

### 1.2　索引与记录定位

`data/train/<场景名>/Label_Index.json` 是 UTF-8 JSON 对象。键为以 `pr-` 开头的物理 ID，值含 `filepath: str` 和 `linenumber: int` 两个字段。序号从 1 开始，布尔值和越界位置无效。路径相对场景目录，规范形式带 `data/` 前缀。runner 会剥去此前缀再从数据目录解析，并检查路径仍在该目录内。采集目录名随场景变化。预测阶段只使用索引和日志，公开答案 `Label.json` 由评分器在预测完成后使用。

| 日志文件 | 第 N 条的含义 | runner 提供的正文 |
| --- | --- | --- |
| `ecar.json`、Zeek 的 `conn.json`、`dns.json`、`http.json` 等 | JSONL 文件第 N 个物理行，计数保留空行 | 非空行经 JSON 解析，本包事件通常为对象。空行返回带原行内容的 `{"raw_text": ...}`。 |
| `windows_event_sysmon.xml`、`windows_event_security.xml` | 第 N 个完整 `<Event>…</Event>`，可跨多行 | `{"raw_text": "<Event>...</Event>"}`。读取后再解析频道、系统事件号及事件字段。 |
| `syslog.log`、`web_access.log` 等文本 | 第 N 个物理行 | `{"raw_text": "..."}`，去除行末换行。 |
| `bash_history/*.bash_history` | 第 N 个由 `#` 加十进制 Unix 时间戳开头的命令组 | `{"raw_text": "...", "timestamp": 整数或 null}`。多行命令保留换行。当前 runner 对完全没有标记的文件按非空行分组，有标记时将首个标记前的文本并入第一条。 |

输入包的数据路径、日志类型清单及格式说明见 [README](../README.md) 和 [索引字段说明](./Label_Index_字段说明.md)。边界行为以 [实际读取实现](../submission_agent/runner.py) 为准。

## 2　比赛输出与运行状态

| 字段 | 本系统输出类型 | 写出约定 |
| --- | --- | --- |
| `physical_id_set` | `list[str]` | 所有已判定为攻击记录的物理 ID。按 ID 去重并稳定排序，允许空数组。这里覆盖整场调查，保留超过战术前三名的有效记录。 |
| `ta_physical_ids` | `dict[str, list[str]]` | 键形如 `TA0002`（`^TA\d{4}$`）。每个值包含 1 至 3 个不同物理 ID，按证据优先级排列。无候选就省略该战术，整个映射允许为空。 |

**写出前检查。** 顶层键必须恰好为上述两项。两个字段中的 ID 均须属于本场景索引。导出器还保证每条战术证据都在 `physical_id_set` 中。当前 runner 主要验证结构、战术键和非空字符串，场景 ID 成员关系、去重和上述子集关系由本系统的 Verifier 与导出器落实。内部攻击链、RAG 引用、置信度及运行诊断保存在案件结果或账本中。

**评分兼容。** 评分器也接受单个字符串作为某战术的值。A 榜本地脚本使用 `--ta-evidence-limit 3`，评分器只取每个列表的前三项。重复 ID 会占用战术候选位置，因此应先按物理 ID 去重再截断。评分器还依据 `physical_id_set` 对照标准答案计算物理记录与攻击步骤得分，提交方无需构造攻击步骤字段。[评分器](../scoring/score_predictions_v2.py) · [本地测试脚本](../scripts/test_local.py)

| 文件或状态 | 生产者与语义 |
| --- | --- |
| `$ANSWER_PATH/<场景名>/predict.json` | runner 校验返回对象后写 UTF-8 JSON，使用临时文件替换目标。正常零命中返回 `{"physical_id_set": [], "ta_physical_ids": {}}`。 |
| `$ANSWER_PATH/done.txt` | runner 的批次完成标记。多场景中某场景抛异常时，当前实现尝试给该场景写空预测，继续处理其他场景，结束时返回非零退出码。判定成功应同时核对退出码和产物。 |
| `.local-output/run-*/scores/<场景名>/evaluation.json` | 本地测试脚本调用评分器产生。该报告属于评测阶段，预测子目录在同一次运行的 `predictions/` 下。 |

## 3　内部数据对象与 ID 约定

以下是拟实现的 v1 接口。签名中的 `ctx` 代表绑定当前案件的上下文。数组用 `[]` 表示无元素，显式未知的可空字段用 `null`。事件时间用带时区的 UTC 字符串，原始值和精度留在原始记录或解析元数据中。

| 对象 | 必需字段与可空字段 | 约束 |
| --- | --- | --- |
| `RunContext` | `case_id, run_id, data_snapshot_id, mapping_version, ruleset_version, knowledge_snapshot_id: str` | 固定本次运行的数据、映射、规则和知识版本。调度器另保存预算、引擎版本及停止原因。 |
| `RawRecord` | `physical_record_id: str, payload: dict, locator: Locator 或 null` | 比赛适配中，设计文档的 `raw_id` 直接使用原始 `physical_record_id`。`Locator` 只含 `filepath, linenumber`。物理记录可按 ID 回查。 |
| `Event` | `event_id, physical_record_id: str`，`source_type, event_time: str 或 null`，`fields: dict` | 单条物理记录可展开出多个事件。事件 ID 由场景、物理 ID 和稳定子记录键确定。回放复用 ID，转换后保留原物理 ID。 |
| `Hit` | `hit_id, rule_id, rule_version, engine, engine_version: str`，`event_ids, tactic_ids: list[str]` | 每条事实性命中可回查组成事件。仅有聚合计数时允许 `event_ids=[]`，以调查线索处理。工具行号和操作系统事件号各有独立命名空间。 |
| `KnowledgeRef` | `retrieval_id, doc_id, chunk_id, version, locator, excerpt, match_reason: str` | 定位检索快照中实际返回的原文。仅用于规则解释、调查规划或构建替代假设。 |
| `Finding` | `claim: str, status: observed / hypothesis / disputed, evidence_event_ids: list[str], knowledge_refs: list[KnowledgeRef], tactic_ids: list[str]` | `observed` 须有本案取证查询支撑。`hypothesis` 可只有资料引用。观察到行为与将物理记录判为攻击分别记录。 |
| `Edge` | `from_event_id, to_event_id, relation: str`，`join_keys: dict, evidence_event_ids: list[str], status: proposed / verified / disputed` | 保存实体或时间关联依据。校验后的有向边参与组链，时间邻近和共享地址可用于发起补查。 |

证据映射方向为 **引擎行号 → event_id → physical_record_id → 本场景索引**。适配器在扫描批次内维护第一步映射，归一化层维护后两步。知识检索、Agent 任务和规则命中使用各自的 ID，不能作为 `pr-…` 的替代值提交。

## 4　处理与只读查询接口

下表的调用名用于模块联调。工程可通过函数、对象方法或绑定了 `ctx` 的工具注册表提供这些能力。下表的返回值均在当前 `case_id/run_id` 的作用域内。

| 调用与职责 | 输入约定 | 成功返回与边界 |
| --- | --- | --- |
| `normalize(ctx, raw)`　转换层 | 单条 `RawRecord`、固定映射版本 | `{events: list[Event], gaps: list[str]}`。部分字段未知时保留可用字段。完全无法解析时返回空事件列表并记录原因，原始记录仍可查。 |
| `detect(ctx, events, ruleset_version)`　Sigma 适配器 | 可重放的事件批次和规则快照，按日志源与引擎能力选择规则 | `{hits: list[Hit], coverage: list[RuleRun]}`。`RuleRun` 包含规则 ID、引擎、状态和原因；状态为 `ran / partial / skipped / failed`。成功零命中写 `ran` 和空命中列表。 |
| `fetch_raw_evidence(ctx, physical_ids)`　证据库 | 本场景物理 ID 数组 | `{query_id, records: list[RawRecord], missing_ids}`。记录按请求 ID 回查。事件引用先通过事件表反查物理 ID。 |
| `query_events(ctx, task_id, filters, limit, cursor?)`　主机或网络调查 | 主机、实体、日志源、进程或连接标识，及可选 UTC 时间窗 `[start,end)` | `{query_id, events, next_cursor}`。以稳定排序分页，末页游标为 `null`。谱系和流关联工具可以返回候选 `Edge`，并保留支撑事件。成功的空集记录查询范围。 |
| `search_knowledge(query, filters, top_k, snapshot_id)`　RAG 工具 | 已绑定调用角色与 `ctx`。支持资料类型、产品、版本、规则 ID、字段名或 `logsource` 过滤；`top_k` 为正整数 | `{retrieval_id, refs: list[KnowledgeRef]}`。按可见范围与快照检索，零匹配返回空列表。服务不可用时记录降级，调查可继续查询本案事件。 |
| `validate_candidate(ctx, kind, candidate, fixtures)`　映射或规则维护 | `kind=mapping / sigma_rule`，候选变更、目标引擎，以及预期命中和正常样本 | `{passed, diagnostics, replay_diff}`。映射核对类型、记录数和来源，规则检查编译与命中变化。维护模块发布通过验证的新版本，当前运行继续引用原快照。 |

## 5　Agent 交接与确定性合并

1. **派单。** `plan(ctx, state_snapshot) → list[Task]`。`Task` 含 `task_id, role, question, target_entities, time_window, stop_condition`。主机和网络角色可并发，Challenger 根据疑点独立检索替代解释并回查原文。
2. **提交。** `submit_findings(ctx, submission) → MergeReceipt`。请求含 `task_id, submission_id, query_ids, findings, edges`。每个观察性结论引用本任务实际取回的案件事件。知识引用另列，知识查询不能充当取证查询。
3. **合并。** `MergeReceipt` 含 `submission_id, accepted_event_ids, rejected_refs, state_version`，每个拒绝项记录引用与原因。同一运行中，相同提交 ID 和内容重试返回原回执；同 ID 不同内容返回冲突。并发提交按事件 ID、边的端点和类型去重，保留反对证据与来源。
4. **复核。** `verify(ctx, state_snapshot) → {verified_state, errors, unresolved}`。逐项校验来源和关系。Repair 只针对可修复的错误补查，使用同一提交入口。角色越权、跨案引用、无法回查的事件或资料冒充证据均记录原因。
5. **导出。** `rank(ctx, verified_state) → CaseResult` 产生候选链、战术证据和未决项。为比赛导出保留 `attack_event_ids: list[str]` 与 `tactic_ranked_event_ids: dict[str,list[str]]`。`to_prediction(ctx, case_result) → Prediction` 将已判定攻击的事件映射为物理 ID，再对每个战术按既有优先级去重并截取前三。资料相似度、Agent 票数和仅供背景的事件都不能单独产生攻击判定。

**失败约定。** 内部工具失败向调度器返回 `{error: {code, message, retryable}}`。至少区分 `INVALID_ARGUMENT`、`OUT_OF_SCOPE`、`ENGINE_ERROR`、`RETRIEVAL_UNAVAILABLE` 和 `BUDGET_EXHAUSTED`。可用分支继续工作，软预算触顶时收束，部分完成时导出已经验证的证据并在账本登记缺口。索引损坏导致官方读取器抛异常时，场景进入第 2 节的 runner 异常路径。运行错误的详情写入内部诊断，不添加到比赛 JSON。

## 6　最小联调样例

以下为独立构造的格式样例。ID 只在这个示例场景中有效。

**索引输入**

```json
{
  "pr-111111111111111111111111": {"filepath": "data/H1/ecar.json", "linenumber": 1},
  "pr-222222222222222222222222": {"filepath": "data/H1/ecar.json", "linenumber": 2}
}
```

设第一个物理记录展开为 `ev-a1` 和 `ev-a2`，第二个展开为 `ev-b1`。调查还引用了一条编号为 `kb-playbook-7` 的手册。假设复核结果已将这三条事件判为攻击，并将 `ev-a1` 和 `ev-a2` 都选作 `TA0002` 的候选证据，则导出如下。

```json
{
  "physical_id_set": [
    "pr-111111111111111111111111",
    "pr-222222222222222222222222"
  ],
  "ta_physical_ids": {
    "TA0002": ["pr-111111111111111111111111"]
  }
}
```

两条同源事件在战术列表中占一个位置。第二条物理记录进入总集合，即使它没有进入该战术的前三。手册可由调查账本回查。

## 7　接口验收

| 用例 | 预期结果 |
| --- | --- |
| 第 2 行 JSONL、第 2 个多行 XML Event、第 2 个含多行命令的 Bash 组、第 2 行 syslog | 四者分别返回对应正文与索引键，原始物理 ID 保持一致。 |
| 空预测、无候选战术、战术键误写成技术编号 | 完整空预测合法；无候选战术省略；`T1059` 作为战术键由入口拒绝。 |
| 同一战术有四个不同候选，另有两条子事件同源 | 导出先按物理 ID 去重，再保留前三。全部已判定为攻击的物理 ID 仍可进入总集合。 |
| 已发布规则运行零命中、缺少日志源、检测器崩溃 | 三者的覆盖状态可区分，均可追溯到规则和引擎版本。 |
| RAG 只返回历史案例、跨案取证、只返回聚合计数 | 前者可生成待查项，跨案请求被拒绝，聚合计数保留为线索。三者均不能直接增加输出 ID。 |
| 相同提交重复送达、主机和网络发现到达顺序颠倒 | 幂等回执可重放。相同的有效证据与排序依据产生相同的比赛输出。 |
| 单场景联调 | 在仓库根目录运行 `python3 scripts/test_local.py --scene 2024-05-30-apt28`。核对退出码、场景预测、批次标记及该场景的评分报告。 |

回归时，既调用 runner 的 `validate_prediction`，也调用评分器的 `parse_prediction(..., ta_evidence_limit=3)`。场景 ID 成员关系、战术证据子集和截断前去重另由系统自身的导出测试覆盖。
