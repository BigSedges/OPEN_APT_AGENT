# OPEN_APT_AGENT 项目交接

交接基线为 `2026-11-28` 的 `origin/y3u1`，实现提交为 [`d6015d6`](https://github.com/BigSedges/OPEN_APT_AGENT/commit/d6015d6)。项目已能单遍读入场景日志、运行本地检测与证据核验，并输出官方评分器接受的预测。当前主要缺口是实战检测质量。已完成的 DeepSeek 单场景运行只检出 27 条标注记录中的 1 条。

## 1. 安装与配置

### Python 环境

在 Ubuntu 或 WSL Ubuntu 的仓库根目录执行。项目使用 Python 3.12，依赖由 `uv.lock` 固定。pySigma、SQLite 后端和本地 `apt-rag` 包随根项目同步。

```bash
# 系统尚未安装 uv 时执行第一行
curl -LsSf https://astral.sh/uv/0.13.6/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
cd /home/yue/OPEN_APT_AGENT
uv python install 3.12
uv sync --locked
```

依赖已缓存时可用 `uv sync --locked --offline`。新环境选用本机架构对应的工具发行包。 [uv 安装说明](https://docs.astral.sh/uv/getting-started/installation/) · [uv 命令参考](https://docs.astral.sh/uv/reference/cli/)

### 检测工具与规则

下表记录这次 Ubuntu x86-64 环境实际使用的版本。下载对应发行包，分别解压到独立目录。保留发行包内的运行资源，并确认 Linux 可执行文件有执行权限。每台机器的安装位置通过配置注入。

| 工具 | 已验证版本与安装包 | 在 `engines` 中配置 |
| --- | --- | --- |
| Zircolite | 4.8.0，解压 `Zircolite-4.8.0-linux-x64.zip`，保留二进制旁的 `_internal`。 [发行包](https://github.com/wagga40/Zircolite/releases/tag/v4.8.0) | `zircolite.bin_path` 指向 `Zircolite`，`rules_dir` 指向 Sigma YAML，`config_path` 指向 `script/log_convert/configs/zircolite_config.yaml` |
| Hayabusa | 4.5.0，解压 `hayabusa-4.5.0-lin-x64-gnu.zip`，保留发行包同版规则与配置。 [发行包](https://github.com/Yamato-Security/hayabusa/releases/tag/v4.5.0) | `hayabusa.bin_path` 指向 Linux 二进制，`rules_dir` 指向 Hayabusa 规则根，`config_path` 指向包含 `channel_eid_info.txt` 的目录 |
| Takajo | 2.16.1，解压 `takajo-2.16.1-lin-x64-gnu.zip`，保留 `libduckdb.so`。 [发行包](https://github.com/Yamato-Security/takajo/releases/tag/v2.16.1) | `takajo.bin_path` 指向二进制或启动包装脚本，`working_dir` 设为 Takajo 安装目录。它读取 Hayabusa 生成的时间线 |
| RSigma | 0.28.0，解压 `rsigma-x86_64-unknown-linux-gnu.tar.gz` 中的 `rsigma`。 [发行包](https://github.com/timescale/rsigma/releases/tag/v0.28.0) | `rsigma.bin_path`、`rules_dir`、`config_path`，配置用 `script/log_convert/configs/rsigma_pipeline.yml` |
| Chainsaw | 2.18.0，从 `chainsaw_x86_64-unknown-linux-gnu.tar.gz` 取二进制，从同版本带规则的 ZIP 取映射。 [发行包](https://github.com/WithSecureOpenSource/chainsaw/releases/tag/v2.18.0) | `chainsaw.bin_path`、`rules_dir`、`mapping_path` 用于 Windows JSON，`config_path` 用 `script/log_convert/configs/chainsaw_custom_mapping.yml` 处理其他日志 |
| pySigma | 根项目的 Python 依赖，随 `uv sync --locked` 安装 | `pysigma.rules_dir` 指向待检查的 Sigma YAML，无需填写 `bin_path` |

Zircolite、RSigma、Chainsaw 和 pySigma 可以配置经过筛选的 SigmaHQ 规则目录。Hayabusa 使用自己的规则和配置。记录每次评测所用规则包的版本、归档或文件哈希。交接机已安装工具位于 `/home/yue/experience/`，通用规则路径为 `/home/yue/experience/rules`，这份目录的规则包发布版本还有待补录。 [SigmaHQ 规则包](https://github.com/SigmaHQ/sigma/blob/master/Releases.md) · [仓库转换与映射说明](../script/log_convert/README.md)

交接机的 Chainsaw Windows JSON 映射是在同版 `sigma-event-logs-all.yml` 上将 `kind: evtx` 改为 `kind: json` 得到。新机器可用下面的命令创建同样的本地文件。Takajo 如果找不到 `libduckdb.so`，让启动进程的 `LD_LIBRARY_PATH` 包含其安装目录，或使用设置该变量后调用二进制的本地包装脚本。

```bash
CHAINSAW_DIR="$HOME/experience/chainsaw"
if [ ! -f "$CHAINSAW_DIR/mappings/sigma-event-logs-json.yml" ]; then
  sed 's/^kind: evtx$/kind: json/' \
    "$CHAINSAW_DIR/mappings/sigma-event-logs-all.yml" \
    > "$CHAINSAW_DIR/mappings/sigma-event-logs-json.yml"
fi
```

### 本地配置与验证

首次配置时从 [本地模板](../config/local.example.yaml) 复制 `config/local.yaml`，按上表替换路径。复制命令会保留已经存在的文件。

```bash
[ -f config/local.yaml ] || cp config/local.example.yaml config/local.yaml
chmod 600 config/local.yaml
export APT_AGENT_CONFIG="$PWD/config/local.yaml"
git check-ignore -- config/local.yaml
```

跨工作目录运行时，给规则、引擎配置、知识库及快照根目录使用绝对路径。离线检索用 `rag.mode: bm25`、`rag.offline: true` 及仓库内 `packages/apt-rag/public_kb/chunks.jsonl.gz`。规则种子门槛为 `minimum_seed_level`，默认 `medium`。检测 CLI 各有 `timeout_s`。调查预算从接入阶段开始计时，长场景的检测开销可能吃掉后续规划时间。首次接手可先跑离线回归。

```bash
uv run --locked --offline pytest -q
uv run --locked --offline python -B packages/apt-rag/tools/langgraph_rag/smoke.py
```

装好真实工具后，可在同一虚拟环境内用仓库的合成场景核对引擎覆盖。下面的冒烟检查显式关闭 LLM，仅输出覆盖状态。

```bash
uv run --locked --offline python - <<'PY'
from collections import Counter
from pathlib import Path
from apt_agent.config import load_config
from apt_agent.ingestion import load_indexed_records
from apt_agent.pipeline import investigate_records

root = Path("tests/fixtures/e2e/scenarios/scene_01_phishing_c2")
cfg = load_config(
    "config/local.yaml",
    env={},
    overrides={"llm": {"enabled": False}, "rag": {"offline": True}},
)
records = load_indexed_records(root / "Label_Index.json", root / "data")
case = investigate_records(records, config=cfg)
for (engine, status), count in sorted(
    Counter((item.engine, item.status) for item in case.coverage).items()
):
    print(engine, status, count)
print(case.stop_reason)
PY
```

在线规划启用 `llm.enabled: true`，并把 `llm.provider` 设为项目识别的 `openai_compatible`。下面是这次评测使用的 DeepSeek 配置示例。密钥放在同一个 WSL 终端的 `APT_AGENT_LLM__API_KEY`，或放进权限为 `600` 且已被 Git 忽略的本地 YAML。环境变量优先级及其他键见 [根 README](../README.md) 和 [环境模板](../.env.example)。 [DeepSeek 兼容接口](https://api-docs.deepseek.com/quick_start/agent_integrations/)

```yaml
llm:
  enabled: true
  provider: openai_compatible
  base_url: "https://api.deepseek.com"
  model: "deepseek-flash"
```

```bash
IFS= read -rsp 'LLM API key: ' APT_AGENT_LLM__API_KEY
export APT_AGENT_LLM__API_KEY
printf '\n'
```

### 用外部 starter 跑分

在外部 starter 的自行维护副本中，让 `submission_agent/runner.py` 里的回调转发到项目公开入口。starter 继续负责读取 `Label_Index.json`、调用回调、生成 `predict.json` 和 `done.txt`。如果外层能提供当前场景的索引上下文，可额外传入 `valid_physical_ids` 和 `locator_map` 保留位置与显式范围校验。默认入口从收到的记录流建立允许的物理 ID 集合。

```python
from apt_agent import analyze_records as run_apt_investigation

def analyze_records(records):
    return run_apt_investigation(records)
```

从项目的 `uv` 虚拟环境启动 starter 的本地评分脚本。保留 `--scene` 仅跑单场景。去掉 `--scene` 会按 starter README 评测全部三个公开场景。预测阶段使用索引和原始日志，标准答案 `Label.json` 由评分器在预测结束后读取。

```bash
APT_AGENT_PROJECT_ROOT=/home/yue/OPEN_APT_AGENT
APT_AGENT_STARTER_ROOT="$HOME/A/apt-agent-a-starter"
export APT_AGENT_CONFIG="$APT_AGENT_PROJECT_ROOT/config/local.yaml"
(
  cd "$APT_AGENT_STARTER_ROOT"
  "$APT_AGENT_PROJECT_ROOT/.venv/bin/python" scripts/test_local.py --scene 2024-05-30-apt28
)
```

如需复现下文的 LLM 运行预算，可在启动前设置 `export APT_AGENT_BUDGET__WALL_CLOCK_S=900`。

验收时检查进程退出码、`predictions/done.txt`、场景的 `predict.json` 和 `scores/<场景名>/evaluation.json`。路径相对 starter 输出的本次运行目录。开启 LLM 后还要确认实际请求成功并通过计划校验。项目的 Lead 在多个可安排任务及可用预算存在时才会发出请求。

## 2. 已交付的框架与验证结果

| 环节 | 当前行为 | 实现入口 |
| --- | --- | --- |
| 接入和证据回查 | 单次消费物理记录，归一化 6 类 16 种输入，保留原始证据、事件到物理 ID 的映射和解析缺口 | [ingestion](../src/apt_agent/ingestion/) · [日志类型](../LOG_TYPE.md) |
| 检测汇总 | 复用 19 个转换脚本共享的解析及格式化模块和 3 份引擎配置。统一引擎命中与覆盖状态，按 YAML 规则的产品和服务约束核对命中 | [转换模块](../script/log_convert/) · [引擎适配](../src/apt_agent/detection/) |
| RAG 与工具权限 | 复用 apt-rag，保留可独立调用的 LangGraph v1 `search_knowledge`。管线中的知识引用和案件取证有独立来源。工具注册表校验角色、案件和作用域，记录审计并约束维护工具的草稿路径 | [apt-rag](../packages/apt-rag/) · [工具注册表](../src/apt_agent/tools/registry.py) |
| 调查和合并 | Lead 基于检测种子生成有预算的候选任务，可调用 LLM 排序。主机和网络分支做只读取证，Challenger 回查待定关系。黑板按查询来源合并，支持并发提交和幂等重试。Verifier 与 Ranker 复核关系和证据顺序 | [调查调度](../src/apt_agent/agents.py) · [黑板](../src/apt_agent/blackboard.py) |
| 维护和快照 | `validate_candidate` 做映射字段保全与样本检查，支持 pySigma 检查及 RSigma 的 Sigma 单规则、关联规则正负样本回放。提供基线规则时记录命中差异。转换与规则维护接口接收候选文本，通过校验后发布版本化快照 | [维护接口](../src/apt_agent/maintenance.py) |
| 标准入口与诊断 | `analyze_records()` 导出 `physical_id_set` 与 `ta_physical_ids`。战术证据限于物理集合，先按物理 ID 去重，再取每个战术的前三条。`investigate_records()` 返回候选链、覆盖、停止原因和审计 | [分析入口](../src/apt_agent/pipeline.py) · [接口规范](Sigma多Agent调查系统接口规范.md) |

交接基线跑通了 **292 项**锁定依赖的离线回归及 **5 项** LangGraph 搜索工具冒烟检查。已在本机用真实工具跑过合成场景，并用真实 RSigma 验证了单条规则与时间关联规则的正负样本。公式和指标以 starter 的评分器为准。

### 官方场景实测

两轮都通过 `2024-05-30-apt28` 的官方读取、预测校验和评分流程。此次评测在进程内绑定 starter 回调，使用该仓库实际的 runner 和 scorer。第 1 节给出接入 starter 副本的方式。

| 运行 | 工具与预算 | 提交物理 ID | 真阳性 / 总标注 | 误报 | 正确战术 | 官方分数 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 无 LLM，日志源修复后 | Zircolite、Hayabusa、RSigma，墙钟预算 150 秒 | 6,832 | 1 / 27 | 6,831 | 0 / 2 | 0.020447 / 100 |
| DeepSeek Flash | `local.yaml` 的 6 个工具，运行时墙钟预算 900 秒 | 6,989 | 1 / 27 | 6,988 | 0 / 2 | 0.019989 / 100 |

DeepSeek 返回了针对 15 个候选任务的有效排序，项目采用了该计划。只发起 1 次模型请求，耗时 3.29 秒，共 1,133 tokens。官方 runner 退出码为 0，生成了预测与 `done.txt`。本轮在内存中启用 LLM、将 provider 映射为 `openai_compatible` 并增加预算，本地配置文件保留原值。两轮工具与预算不同，分差无法归因于 LLM。WSL 当次报告路径如下，`/tmp` 由系统清理，表中保留可供交接的指标。

- 无 LLM 评分报告 `/tmp/open-apt-agent-official-qw6jj_2n/evaluation.json`。
- LLM 评分和运行报告 `/tmp/open-apt-agent-llm-eval-jsj2vzfe/evaluation.json` 与 `/tmp/open-apt-agent-llm-eval-jsj2vzfe/runtime.json`。

## 3. 待完成事项

1. **定位漏检和误报，再改判断规则。** 用 `investigate_records()` 取得现有核验与覆盖诊断，再补齐按物理 ID 追踪接入、归一化、引擎命中、日志源过滤、调查种子和战术排序的观测。只在预测之后用评分报告做漏检归因。优先记录哪些标注证据在各阶段失去，按高频误报规则及日志源做负样本回放。能复现归因后再改映射、规则或排序。
2. **固化评测配置并补齐对照。** 在独立 starter 副本应用公开回调，固定引擎版本、规则与知识快照、门槛、预算和输出目录，覆盖 `2024-05-30-apt28`、`apt29-adfs`、`uat4356`。仅切换 LLM 开关，记录各场景的分数、请求是否实际发生、阶段耗时与预算终止理由。需要比赛提交时，把项目及其依赖接入 starter 的容器构建并做运行验收。
3. **补齐调查角色和执行编排。** 当前 LLM 的实际职责是排序既有只读任务。Repair 已能通过同一黑板提交入口补查证据，自动识别失败分支、派修和复验的闭环待补。主机与网络当前按确定性顺序执行，独立 Agent 调度、并行执行与取消需要在实测预算下验证。预算耗尽和检测阶段超时应在运行报告中清楚区分。
4. **完善维护与可复现发布。** 转换和规则维护 Agent 当前处理调用方提供的候选。候选生成、未知字段的协作调查，以及全部实际目标引擎的编译、回放和失败隔离仍需完善。目前映射快照自动绑定覆盖 Zircolite 与 Chainsaw，显式引擎路径优先。补齐其他引擎映射绑定，并为本地规则目录补版本指纹，验证新快照发布时旧案件可按原资源复现。
5. **保留可交接的案件诊断。** 公开入口已能返回 `CaseResult`。为持续评测增加脱敏的持久运行报告，记录提交 SHA、工具和规则版本、候选证据的阶段流转、各引擎覆盖、模型审计与最终评分。

## 4. 交接前 Gemini Teamwork 计划

以下保留原计划的工作目标和验收口径，供接手后按里程碑推进。工作目录为 `/home/yue/OPEN_APT_AGENT`，`Integrity mode: demo`。团队不得复制其他开源项目的代码作为核心逻辑，不得在实现前阅读测试源码推断预期行为。以设计和接口规范推导行为，提交实现后按验收清单运行测试和外部验证。

原计划的 R1–R4 如下。

1. **R1 核心多 Agent 日志调查。** 结合仓库的 `packages/apt-rag/` 和 `script/log_convert/`，实现案件与事件模型、归一化、原始证据库和多检测引擎适配。接入 LangGraph 外部工具 `search_knowledge`。实现 Lead、主机、网络、Challenger、Verifier、Repair、Ranker 协作与确定性黑板合并、核验和导出。
2. **R2 Agent 工具与维护。** 封装并注册 `read`、`bash`、`write`、`edit` 及检索与取证工具，按角色、案件和读写边界授权，拒绝越权并留审计。实现转换与规则 Agent 及 `validate_candidate`。覆盖未知字段与映射变更、Sigma 单规则和关联规则、语法与 Schema、目标引擎编译、正负样本和基线差异回放。发布新快照时保有当前运行绑定的原快照。
3. **R3 工程环境和外部入口。** 用 `uv` 统一包名、Python、依赖和运行命令，复用现有检索与转换模块。实现只消费一遍的 `analyze_records(records: Iterator[tuple[str, dict[str, Any]]]) -> dict[str, Any]`，遵循 `Label_Index.json` 边界和两个预测字段。引擎、规则集、LLM 和预算参数由配置注入，外部 starter 路径只出现在外部联调环境或操作文档。
4. **R4 分阶段验证与外部评测。** 先完成项目自身的离线验证，再由用户填写 LLM 配置。评测阶段在外部 starter 的 `submission_agent/runner.py` 补公开回调，按 starter 文档运行场景和评分，保留有效预测与评分报告。

验收清单以 [接口规范第 7 节](Sigma多Agent调查系统接口规范.md) 和 [设计原型验收](Sigma多Agent日志调查系统设计.md#原型验收用例) 为准。移交时至少核对以下各项。

- `uv` 可同步并执行回归。检索、转换和调查调用链可联通，路径和模型参数可注入。
- 验证多格式物理记录定位与回查、空预测与非法战术键、同源子事件按物理 ID 去重后截断前三、覆盖状态区分、RAG 隔离与降级、并发与幂等、可复现排序。
- 越权或超出作用域调用被拒绝且可审计。维护验证覆盖映射和 Sigma 关联规则，正负样本及回放差异可核对，旧运行的资源版本可复现。
- 预测 ID 属于当前索引，战术证据是物理集合子集。外部 starter 能用公开入口生成有效预测和评分，项目源码与配置保持路径独立。

接手阶段曾查阅已有端到端测试源码后再补齐实现，与 demo 约束要求的验证顺序有出入。已实现的产品功能与评分结果如第 2 节，后续团队按上述约束验收新增实现。

原计划资料包括 [README](../README.md)、[LOG_TYPE](../LOG_TYPE.md)、[调查系统设计](Sigma多Agent日志调查系统设计.md)、[调查系统接口规范](Sigma多Agent调查系统接口规范.md)、[LangGraph 外部工具规范](LangGraph外部工具接入规范-v1.md)、[RAG](RAG.md) 和 [日志工具说明](日志.md)，以及 [apt-rag](../packages/apt-rag/) 与 [log_convert](../script/log_convert/)。
