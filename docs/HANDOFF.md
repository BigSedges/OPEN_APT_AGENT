> GitHub 最新交接入口：[HANDOFF-2026-11-28.md](HANDOFF-2026-11-28.md)。源码已归入本仓库，附件位于 docs/artifacts/handoff-2026-11-28/。

# OPEN_APT_AGENT 项目交接

> 最新交接（2026-11-28）：请先阅读 [当前检查点](HANDOFF-2026-11-28-CHECKPOINT.md)。其中明确最新工作副本、338 项回归、三场景离线结果和未完成的 LLM 对照；下文保留历史记录。

本交接以 `2026-11-28` 已合并到 `main` 的 [实现提交 `d6015d6`](https://github.com/BigSedges/OPEN_APT_AGENT/commit/d6015d6) 为准。项目已能单遍读入场景日志、运行本地检测与证据核验，并输出官方评分器接受的预测。当前主要缺口是实战检测质量。已完成的 DeepSeek 单场景运行只检出 27 条标注记录中的 1 条。

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

## 2. 已实现的行为与当前边界

### R1 日志调查主链路

`analyze_records()` → `ingest_records()` → `Normalizer.normalize_batch()` → `DetectionCoordinator.detect()` → `run_investigation()` → `verify()` / `rank()` → `to_prediction()`。调试时用 `investigate_records()` 跑同一条主链路并取回 `CaseResult`。 [分析入口](../src/apt_agent/pipeline.py) · [结果模型](../src/apt_agent/models.py)

| 组件 | 已实现且可调用 | 当前边界 |
| --- | --- | --- |
| 索引读取与原始证据 | `load_indexed_records()` 按 `Label_Index.json` 读取 JSONL、Windows XML、文本和 Bash 历史。接入层单遍消费 `(physical_record_id, payload)`，拒绝重复 ID 和显式范围之外的 ID，保存可回查的原始记录 | 公开回调只收到记录迭代器时，范围由收到的记录确定。文件和行号定位依赖调用方传入 `locator_map`。 [接入和索引读取](../src/apt_agent/ingestion/store.py) |
| 日志归一化 | 支持 Windows Event XML、Zeek、eCAR、syslog、Web access、Bash history，共 6 类 16 个子类型。复用 `script/log_convert/` 的解析器、格式化模块及 3 份引擎配置。保留事件 ID 到物理 ID 的映射，并输出解析缺口 | 输入按场景存入内存。未知字段、未知格式和不完整记录的后续处理有待按实际场景扩充。 [归一化](../src/apt_agent/ingestion/normalizer.py) · [日志类型](../LOG_TYPE.md) · [转换层](../script/log_convert/) |
| 检测与覆盖 | Zircolite、Hayabusa、RSigma、Chainsaw 输出统一命中。Takajo 接 Hayabusa 时间线做补充，pySigma 做静态规则检查。保留 `ran`、`partial`、`skipped`、`failed`；单个适配器失败可继续其他引擎 | YAML 规则按已识别的产品和服务核对命中。只有计数的关联命中保留为线索。各引擎仍有规则或日志源覆盖差异。 [引擎汇总](../src/apt_agent/detection/coordinator.py) · [日志源校验](../src/apt_agent/detection/routing.py) |
| RAG | 调查管线通过工具注册表调用 `RagService`。Lead 和 Challenger 可取回知识引用。仓库内有离线 BM25 知识库及可独立调用的 LangGraph v1 `search_knowledge`，知识引用和本案日志证据各有独立记录 | 当前 Lead 与 Challenger 使用预设检索问题。案件专有的检索规划及外部知识快照覆盖需继续验证。 [RAG 说明](RAG.md) · [工具协议](LangGraph外部工具接入规范-v1.md) |
| 黑板与输出 | `record_task_query()` 记录取证来源，`submit_findings()` 检查案件、运行和查询引用。同一提交 ID 的相同内容可重试，内容变化返回冲突。Verifier 核查关系，Ranker 确定性排序。导出时把事件映射回物理 ID，战术列表先去重再取前三，且只引用攻击物理集合内的记录 | 并发验收覆盖黑板提交与顺序一致性。完整案件活动存档和逐物理 ID 的阶段轨迹待补。 [黑板](../src/apt_agent/blackboard.py) · [输出契约](Sigma多Agent调查系统接口规范.md) |

#### 调查角色当前如何执行

- **Lead。** 从达到 `minimum_seed_level` 的命中沿已有候选关系生成任务。LLM 只返回已有任务 ID 的排列，缺少配置、任务不足两个、预算不足或调用失败时采用确定性顺序。模型收到任务角色、关系类型和少量知识库摘录。
- **主机与网络。** `run_investigation()` 在同一进程依次用 `query_events` 执行分批取证。主机侧围绕进程关系取证，网络侧核对连接关系。各批次记录查询 ID 并把找到的案件证据交给黑板。实际工作流仍待支持独立并行调度、取消和失败重试。
- **Challenger。** 对待定或有争议的关系再查本案日志和知识库，并提交假设。当前 `max_challenger_rounds` 只用来决定是否执行一次回查。
- **Verifier、Ranker 与 Repair。** 黑板核对查询来源。Verifier 校验同主机关联、五元组、跨源与时间窗口，保留待定和争议。Ranker 根据证据和关系排序。已可用 `repair` 角色通过同一工具和黑板接口补交证据，调度器中的自动派修、重查和复验闭环待实现。
- **预算。** 目前实际约束调查的有墙钟余量、模型 token 余量和任务数。检测工具有各自的 `timeout_s`。`max_steps_per_task` 和 `max_repair_rounds` 已定义在配置中，尚未接入运行控制。 [调度与预算](../src/apt_agent/agents.py) · [预算配置](../src/apt_agent/config.py)

### R2 工具权限与维护

- **工具权限已接入。** 调查角色可通过 `ToolRegistry` 使用 `read`、`fetch_raw_evidence`、`query_events`、`search_knowledge`。转换与规则维护角色可在受限工作区调用 `read`、`write`、`edit`、`bash`、`query_events`、`search_knowledge`。角色、案件和作用域检查经过回归，越权和工具错误会留下审计。 [工具注册表](../src/apt_agent/tools/registry.py) · [基础工具](../src/apt_agent/tools/base_tools.py)
- **映射候选已能校验。** `validate_candidate(..., "mapping", ...)` 检查 Zircolite `mappings` 或 Chainsaw `groups` 的结构、时间字段及样本的字段值和类型保全。默认要求保留 `event_id`、`raw_id` 和 `@timestamp`。目前这里回放的是字段映射检查，各目标引擎的真实映射运行验收待补。
- **Sigma 候选已能回放。** `validate_candidate(..., "sigma_rule", ...)` 做 pySigma 检查并通过 RSigma 回放正例、反例。关联规则可附带 `base_rules`，提供 `baseline_rules` 时会给出命中增减。现有发布路径仍需扩展到其他目标检测引擎的编译和回放。
- **快照发布已接入。** `ConverterAgent` 和 `RuleAgent` 接收调用方提供的候选与样本，通过校验后发布。`SnapshotRegistry` 拒绝覆盖已存在的版本。路径未显式设置时，运行可按配置绑定规则和知识版本，以及 Zircolite 和 Chainsaw 映射。由未知字段自动提出可审查候选、绑定其他引擎的映射和为显式资源目录生成版本指纹仍待完成。 [校验与版本实现](../src/apt_agent/maintenance.py)

### R3 工程、接口与验证

- **环境和接口已接通。** Python 版本和依赖由 `.python-version`、`pyproject.toml` 和 `uv.lock` 管理，引擎路径、规则集、预算及 LLM 由 YAML、环境变量或调用参数注入。源码和配置模板自身独立于外部 starter 安装目录。 [项目配置](../pyproject.toml) · [本地示例](../config/local.example.yaml)
- **验收有具体回归入口。** [接口验收测试](../tests/e2e/test_acceptance_matrix.py) 中的 `test_s7_1`–`test_s7_6` 分别覆盖物理定位、空预测和非法战术、同源去重与截断、引擎覆盖状态、RAG/跨案/计数线索隔离、幂等与排序。项目库回归 **292 项**通过，LangGraph 搜索协议冒烟 **5 项**通过。另在真实引擎上跑过合成场景，并用真实 RSigma 验证单规则和时间关联规则回放。
- **诊断入口已提供。** `CaseResult` 包含 `event_to_physical`、`coverage`、`edges`、`validation_errors`、`knowledge_refs`、`investigation_ledger` 和 `stop_reason`。它能解释部分证据和关系处置。覆盖报告是规则或引擎级摘要，按单条物理 ID 判断原始命中、被过滤及入种子的全链路记录仍待增加。

### R4 外部评测已验证范围

两轮都通过 `2024-05-30-apt28` 的官方读取、预测校验和评分流程。`apt29-adfs` 和 `uat4356` 的完整运行，以及 starter 容器的交付验证待补。此次评测在进程内绑定 starter 回调，使用该仓库实际的 runner 和 scorer。第 1 节给出接入 starter 副本的方式。

| 运行 | 工具与预算 | 提交物理 ID | 真阳性 / 总标注 | 误报 | 正确战术 | 官方分数 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 无 LLM，日志源修复后 | Zircolite、Hayabusa、RSigma，墙钟预算 150 秒 | 6,832 | 1 / 27 | 6,831 | 0 / 2 | 0.020447 / 100 |
| DeepSeek Flash | `local.yaml` 的 6 个工具，运行时墙钟预算 900 秒 | 6,989 | 1 / 27 | 6,988 | 0 / 2 | 0.019989 / 100 |

DeepSeek 返回了针对 15 个候选任务的有效排序，项目采用了该计划。只发起 1 次模型请求，耗时 3.29 秒，共 1,133 tokens。官方 runner 退出码为 0，生成了预测与 `done.txt`。该次运行的覆盖报告包含 6 个工具，pySigma 记录 1,328 项 `ran`、49 项 `partial`，RSigma 记录 1,374 项 `ran`、3 项 `skipped`。本轮在内存中启用 LLM、将 provider 映射为 `openai_compatible` 并增加预算，本地配置文件保留原值。两轮工具与预算不同，分差无法归因于 LLM。WSL 当次报告路径如下，`/tmp` 由系统清理，表中保留可供交接的指标。

- 无 LLM 评分报告 `/tmp/open-apt-agent-official-qw6jj_2n/evaluation.json`。
- LLM 评分和运行报告 `/tmp/open-apt-agent-llm-eval-jsj2vzfe/evaluation.json` 与 `/tmp/open-apt-agent-llm-eval-jsj2vzfe/runtime.json`。

## 3. 接手后待完成的工作

### P0 定位漏检与误报

- **已知现象。** 官方 `2024-05-30-apt28` 的 LLM 版只检出 1/27 条标注记录，同时提交了 6,988 条误报。当前报告可确认结果和各引擎覆盖，逐条漏检归因尚未完成。
- **改动入口。** 从 `investigate_records()` 的诊断入手，在 `Normalizer.normalize_batch()`、`DetectionCoordinator.detect()`、日志源过滤、`_detection_seeds()`、`verify()` 和 `to_prediction()` 的交界处记录按物理 ID 可关联的阶段结果。按规则、引擎和日志源聚合误报，再做负样本回放。
- **验收。** 先生成预测，再与标注对照。为 26 条漏检分别指出最后通过的阶段及可核对的原因，单列输入缺失或原因待查的记录。为主要误报规则提供命中分布和复现用例。用修复前后可重复的指标验证变化，并用其他场景检查误报与漏检是否转移。

### P0 补完外部评测交付

- **已有证据。** 目前只完成一个官方场景的无 LLM 与 DeepSeek 运行，starter 回调是运行时绑定。两轮工具和预算不同。发布用 starter 适配及完整三场景对照待交付。
- **改动入口。** 在团队维护的外部 starter 副本接上公开入口。固定提交、工具、规则及知识快照、映射、门槛和预算，对 `2024-05-30-apt28`、`apt29-adfs`、`uat4356` 各跑一次离线和一次开启 LLM。需要比赛容器交付时在同一副本验证镜像构建和工具可执行性。
- **验收。** 三场景均保留退出码、`done.txt`、可通过校验的预测和评分报告。对照只切换 LLM 开关，并记录实际有无模型请求、停止原因和耗时。将工具和规则版本、阶段耗时、覆盖及评分写入脱敏的持久产物。

### P1 补齐自动 Repair 与任务调度

- **改动入口。** 在 `run_investigation()` 根据取证错误、待核验关系和预算生成可执行的 Repair 任务，受 `max_repair_rounds`、`max_steps_per_task` 约束。让主机和网络任务按明确策略并行，结果继续经原黑板接口与 Verifier 汇总。
- **验收。** 用一个可修复的缺证据场景展示派修、补证、复验到输出。用一个不可修复或预算耗尽的场景展示停止理由。并发与不同完成顺序下，同一经验证据的排序和预测保持一致。

### P1 补齐维护发布和快照复现

- **改动入口。** 给未知字段输出来源、样本与候选变更，纳入转换 Agent 的评审入口。为每种启用引擎增加相应映射或规则的实际编译、正负样本与基线回放，补齐映射版本绑定与外部资源指纹。
- **验收。** 错误映射和命中负样本的规则都被拒绝发布。正常变更报告各目标引擎的校验和差异。发布新版本后，旧运行仍能拿到绑定的规则、映射及知识内容并重放，这项检查需要覆盖显式挂载的资源目录。

## 3.1 macOS 接手增量（2026-11-28）

本次先推进 P0 的观测能力。`CaseResult.record_diagnostics` 按输入物理 ID 保留归一化事件、日志源、解析告警与缺口、引擎过滤前命中及过滤原因、实际种子、已核验和未决关系、Ranker 攻击判定及最终导出。`seed_event_ids` 记录调度器实际使用的种子；`stage_timings_s` 记录接入、归一化、检测、调查核验排序和诊断耗时。`DetectionResult.hit_trace` 保留合并前来源，原有字典访问的四个键保持不变。比赛 JSON 仍只有两个约定字段。

阶段记录中的 `ranked_attack` 不代表每条种子都有已核验的关联边。当前 Ranker 会把直接规则种子加入攻击集合，再沿部分已核验关系扩展。诊断为导出物理记录区分 `direct_detection_seed` 和 `investigation_expansion`，便于下一步检查误报来源。这是待验证的误报路径，尚不能据此认定接力文档中近七千条误报的根因。

新增入口在仓库根目录运行，配置必须显式指定；输出目录必须尚不存在，避免覆盖以前结果：

```bash
uv run --locked --offline python script/diagnose/run_scene.py   /path/to/starter/data/train/2024-05-30-apt28   --config config/local.yaml --output /path/to/new-run
```

依次生成 `predict.json`、含逐记录追踪的 `case.json` 和 `runtime.json`。该程序不读标注、不写 starter 的 `done.txt`。预测完成后单独对照：

```bash
uv run --locked --offline python script/diagnose/compare_scene.py   --case /path/to/new-run/case.json   --gold /path/to/starter/data/train/2024-05-30-apt28/Label.json   --output /path/to/new-run/comparison.json
```

对照报告包含逐条漏检的最后阶段、原因和追踪；未收到的标注 ID 单列为 `input_missing`。按引擎、规则和日志源统计去重后的物理命中、过滤后命中、导出和误报，并给出误报物理 ID 供负样本回放。规则分组表示该规则与误报记录的命中关系，不表示它是唯一归因；关联扩展产生的误报也可能没有直接规则命中。无事件命中时提示检查覆盖，不能据此宣称引擎已完整扫描。这里的计数不是官方总分。

新增回归从接力文档契约构造过滤、低等级、解析失败、直接种子、输入缺失和标注隔离场景。尚未完成的验收包括原 Linux 六工具配置的复现、26 条历史漏检的逐条归因、负样本修复前后对照、三场景固定条件 LLM 对照及容器交付。P1 的自动 Repair、并行调度和维护快照工作仍保持待办。

### 本次本机验证结果

- Python 3.12.14，按未修改的 `uv.lock` 同步依赖。项目回归 **293 项通过**（含新增 1 项 P0 复合场景）；LangGraph 协议冒烟 **5 项通过**。macOS 的 `/var` 与 `/private/var` 路径别名会触发既有 CLI 测试中的 cwd 字符串比较，验证时使用 `TMPDIR=/private/tmp`。未修改测试断言。
- 在本机已有的 macOS ARM64 Hayabusa **4.4.0** 与同目录规则上，关闭其他检测引擎及 LLM，`minimum_seed_level=medium`、墙钟预算 900 秒，完整读取 APT28 的 **209,109 条**记录，诊断命令退出码为 0，约 **174.23 秒**生成预测与案件诊断。官方评分器命令退出码为 0：**1/27 真阳性、6,010 误报、26 漏检，0.023233/100**。本次没有通过 starter runner，因此没有 `done.txt`，不算完成 R4 交付。
- 本次 26 条漏检中，**15 条最后停在 normalized**（11 条 eCAR、4 条 Windows），**11 条停在 source_accepted**（全部 Windows，只有 informational/low 命中，未达到 medium 门槛）。没有输入缺失或完全解析失败的标注记录。这是本次单引擎运行的逐条归因，不能替代历史 Linux 六工具运行的归因。
- 6,010 条误报中，**5,853 条带直接检测种子、157 条由调查扩展入选**。达到种子门槛的主要关联规则包括 `5c67a566-7829-eb05-4a1f-0eb292ef993f`（External Remote SMB Logon from Public IP，high，4,054 条误报物理记录）、`4386b4e0-f268-42a6-b91d-e3bb768976d6`（Kerberoasting Activity - Initial Query，medium，889 条）及 `f19849e7-b5ba-404b-a731-9b624d7f6d19`（Possible Kerberoasting，medium，889 条）。不同规则命中可重叠，不能相加。
- 下一步用上述误报 ID 经原索引回查，构造独立正负样本，检查公网地址语义、环境背景和攻击判定条件，再固定资产跑修复前后对照。此次只新增观测能力，未根据标注调整检测逻辑，也没有声称检测质量提升。

### P0 修复：IPv4 映射 IPv6 的 CIDR 误报

回查前述误报发现，Windows Security 原文的内网来源地址使用 `::ffff:10.20.x.x`。原转换层把这个字符串原样送进检测器，而对应规则只列出 IPv4 的内网 CIDR，导致它绕过排除条件。该现象已用独立合成样本在真实 Hayabusa 中复现：修复前两个映射内网地址误报，修复后排除；公网 IPv4、映射公网 IPv4 及原生公网 IPv6 三个正例仍命中。

`script/log_convert/lib/formatters.py` 现在在生成 Windows 引擎输入时，将明确地址字段中的有效 IPv4 映射 IPv6 转成等价 IPv4；包含十六进制尾部的映射形式也受支持。四种引擎的 Windows 格式化器共用此行为，原始记录、归一化 Event、ID、原生 IPv6 和非地址字段保留原值。未改外部规则、种子门槛、LLM 或攻击判定逻辑。RSigma、Zircolite、Chainsaw 在本轮验证了输入格式和原文保全；真实引擎 CIDR 回放仅验证 Hayabusa。

固定 Hayabusa 4.4.0、同一规则和知识资产、medium 门槛、900 秒预算，关闭其他引擎与 LLM，预测生成后才调用官方评分器和标注对照程序。修复前后指标如下：

| 场景 | 修复前 TP / FP / FN | 修复后 TP / FP / FN | 官方分数（前 → 后，满分 100） |
| --- | --- | --- | --- |
| APT28 | 1 / 6,010 / 26 | 1 / 1,791 / 26 | 0.023233 → 0.077484 |
| APT29 | 3 / 9,735 / 24 | 3 / 3,525 / 24 | 0.043074 → 0.118621 |

APT28 删除 4,219 条误报且未新增误报，已检出的攻击记录保留。原始规则命中变化仅涉及公网 SMB 登录（4,054 → 0）、公网 RDP 登录（158 → 0）及另一个公网地址规则（7 → 0）。APT29 修复前后均以 `TASK_LIMIT` 停止，预算与任务配置一致，未减少已检出的攻击记录。剩余漏检仍为 APT28 的 26 条、APT29 的 24 条，召回率没有改善；本轮结果不构成 R4 三场景、LLM 或容器交付验收。

新增 `tests/test_windows_address_canonicalization.py`，独立覆盖内网、公网、原生 IPv6、十六进制映射、无效地址、四引擎输入、原文与 ID 保全，并支持通过环境变量执行真实 Hayabusa 正负例回放。设置本机原生工具后，全部回归 **303 项通过**。本轮对照产物包含预测、逐条对照、官方评分、运行耗时、规则变化、独立回放结果，以及核对过的工具、规则、配置与格式化器源码指纹。

后续仍须处理：普通 RC4 票据请求等上下文型告警被直接当作攻击证据、仅低级别命中的攻击上下文未被取回、eCAR 检测引擎覆盖不足，并在独立场景和完整引擎配置下复验。

### P0 漏检增量：eCAR 类型、进程实例及双引擎对照

本轮在本机接入经过官方 SHA256 校验的 RSigma 0.28.0，并固定 SigmaHQ `r2026-07-01` 的 `sigma_all_rules.zip`（归档 SHA256：`5725c91b5813587ad6a4b0b8e0233fa44348b1595f818d8b7fd39d6033385085`）。包内共 3,302 条 YAML，本轮配置其 `rules/` 下 2,842 条规则，不含另一个 emerging-threats 目录。官方来源：[RSigma 发行版](https://github.com/timescale/rsigma/releases/tag/v0.28.0) · [SigmaHQ 固定发行版](https://github.com/SigmaHQ/sigma/releases/tag/r2026-07-01)。

实现增量：

- 转换层按 eCAR object/action 解释 `objectID` 和 `actorID`，区分进程、父进程与文件/模块对象；显式 process_guid 优先，原始属性保留。补齐 `ImageLoaded`、注册表 `TargetObject` / `Details`、进程访问和远程线程的已有字段。
- 给已识别 eCAR 类型生成 `event_categories`，在协调器核对规则 category；generic Windows/Linux endpoint category 的静态兼容性纳入 eCAR，特定 Sysmon/Security service 仍不可冒充。此处新增的 category 核对限定于 eCAR，其他源的完整 category 路由仍待继续完善。
- 只有同主机、明确进程实例标识、唯一创建记录且时间有效时，产生创建至退出区间内的同进程候选关系。取证仍经原查询、黑板和 Verifier。Ranker 对同进程关系允许双向回查，父子关系不会自动判恶；不同主机、创建前、退出后、未知身份不通过此路径。
- RSigma 逐行读取 NDJSON，普通事件仅保留后续使用的 ID/时间，关联组成事件完整保留；案件诊断增量编码，减少完整文本、解析对象和导出副本同时驻留内存。协议、命中和比赛两字段格式不变。

本节前后对照均固定 Hayabusa 4.4.0、RSigma 0.28.0、相同两份规则及知识资产、medium 门槛、900 秒预算和关闭 LLM。上一节为 Hayabusa 单引擎评测。预测持久化后才读取标注。最终普通 CLI 的四次运行均退出 0，APT28 的预测均获官方评分器接受。

| 验证范围 | TP（前 → 后） | FP（前 → 后） | FN（前 → 后） | 官方分数（满分 100） |
| --- | --- | --- | --- | --- |
| APT28 完整 209,109 条索引记录 | 1 → 7 / 27 | 3,607 → 3,449 | 26 → 20 | 0.038644 → 0.281578 |
| APT29 的全部 124,427 条 eCAR 索引记录 | 0 → 6 / 12 | 1,674 → 1,603 | 12 → 6 | 未作全场景官方评分 |

APT29 范围在预测前仅按索引 filepath 的文件名 `ecar.json` 选择，不使用标注选输入；预测后将标准答案物理 ID 与该输入范围求交得到 12 条。该结果只验证 eCAR 迁移，不能当作 APT29 完整场景或 R4 验收。APT28 前后均为 `TASK_LIMIT`；APT29 eCAR 基线为 `INVESTIGATION_COMPLETE`，修复版为 `TASK_LIMIT`，均未耗尽墙钟预算。

APT28 新增 6 条真阳性（4 条 eCAR、2 条 Windows），未丢失已有真阳性；同时移除 995 条旧误报、引入 837 条新误报，净减少 158 条。APT29 eCAR 移除 1,072 条旧误报、引入 1,001 条新误报，净减少 71 条。关联补证仍会扩大错误种子的影响，净计数改善不意味着误报已经收敛。

最终完整回归 **313 项通过**，包含显式 GUID 优先、事件类型隔离、普通/关联输出解析、原文保全、进程区间边界、反向回查、跨主机和子进程隔离，以及真实 RSigma 与 Hayabusa 回放；检索协议冒烟 **5 项通过**。普通入口复跑与较早诊断包装生成的预测逐项一致。曾中止的并行/诊断包装尝试排除在有效运行之外；完整规则回放采用串行方式，避免单进程约 4GB 的旧读取方式造成资源争用。

本机持久产物目录为 `/Users/zhangjunhao/Documents/Codex/2026-11-28/gen/outputs/ecar-recall/`，其中 `report.json`、`manifest.json` 和各范围前后目录保存预测、逐条漏检、官方评分或专项计数、运行停止原因、增删误报 ID、配置及源码/规则/二进制哈希。运行绑定的版本标签仍为 v1，本轮依靠这些哈希区分资产；P1 的完整快照绑定与重放尚未完成。本机本地配置仅启用已经验证的两个检测引擎，其他工具保留 skipped 语义。

下一步 P0：逐条处理剩余 20 条 APT28 漏检，收敛普通 RC4 票据等宽泛种子及关联扩展引入的误报，改进战术证据排序（本轮 APT28 战术仍为 0/2）。当前多条无关原始命中来自 Zeek 的 `not selection` 规则在缺少字段时的匹配，已由日志源检查拒绝；这些记录尚无可用的本源检测证据，不能放宽跨源检查来补召回。完整三场景、仅切换 LLM 的对照和 starter/container 交付仍待完成。

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
