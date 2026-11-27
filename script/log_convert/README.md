# Log Conversion Scripts (`log_convert`)

基于 `日志.md` 中梳理的检测与取证工具（**Zircolite**、**Hayabusa**、**Takajo**、**pySigma**、**RSigma** 及参考对比 **Chainsaw**），面向 `log_example/` 中全部 **16 个日志样本 / 6 类原始日志格式** 编写的标准化转换脚本集，使用 `uv` 管理 Python 虚拟环境与依赖。

---

## 一、`log_example/` 原始日志分类（共 16 个文件 / 6 类格式）

| 原始格式标识 | 包含样本文件 | 说明 |
| --- | --- | --- |
| `winxml` | `windows_event_security.xml`, `windows_event_sysmon.xml` | Windows Event XML（`<Events><Event>...</Event></Events>`） |
| `zeek_json` | `conn.json`, `dhcp.json`, `dns.json`, `files.json`, `http.json`, `ocsp.json`, `pe.json`, `smtp.json`, `ssl.json`, `x509.json` | Zeek JSONL 网络日志（浮点秒级 `ts`、点分字段与列表字段） |
| `ecar_json` | `ecar.json` | MITRE eCAR 端点遥测 JSONL（毫秒级 `timestamp_ms`、嵌套 `properties` 对象） |
| `syslog` | `syslog.log` | Linux RFC 5424 Syslog 文本日志（兼容 RFC 3164 回退） |
| `web_access` | `web_access.log` | Apache/Nginx Combined Log Format Web 访问日志 |
| `bash_history` | `sarah.oconnell.bash_history` | GNU Bash 历史命令日志（`#<epoch>` + 命令行成对记录） |

---

## 二、工具 × 原始格式转换脚本总览（共 19 个脚本）

命名规范：`{tool_name}_{原始数据格式}_{目标数据格式}.py`

| 工具 | 原始格式 | 目标格式 | 脚本文件 | 核心处理要点 |
| --- | --- | --- | --- | --- |
| **Zircolite** | `winxml` | `jsonl` | `zircolite_winxml_jsonl.py` | 扁平化 `System` + `EventData`，避免 SQLite 大小写冲突（`Execution_ProcessID` vs `ProcessId`），注入 `event_id` 与 UTC `@timestamp` |
| **Zircolite** | `zeek_json` | `jsonl` | `zircolite_zeek_json_jsonl.py` | 扁平化点分键（`.` -> `_`）与列表值，补充 `src_ip`/`dst_ip`/`zeek_log_type`、`event_id`、UTC `@timestamp` |
| **Zircolite** | `ecar_json` | `jsonl` | `zircolite_ecar_json_jsonl.py` | 扁平化嵌套 `properties`，映射到 Sigma 字段（`Image`/`CommandLine`/`ParentImage`/`TargetFilename`/`SourceIp` 等），注入 `event_id` |
| **Zircolite** | `syslog` | `jsonl` | `zircolite_syslog_jsonl.py` | 解析 RFC 5424 `PRI`/`facility`/`severity`/`hostname`/`app_name`/`pid`/`message`，注入 `event_id` |
| **Zircolite** | `web_access` | `jsonl` | `zircolite_web_access_jsonl.py` | 解析 Combined 日志为标准 Sigma `webserver` 字段（`c-ip`/`cs-method`/`cs-uri-stem`/`sc-status`/`cs-User-Agent` 等） |
| **Zircolite** | `bash_history` | `jsonl` | `zircolite_bash_history_jsonl.py` | 合并 `#<epoch>` 与命令行，从文件名提取 `User` 并解析 `Image`/`CommandLine`，注入 `event_id` |
| **Hayabusa** | `winxml` | `jsonl` | `hayabusa_winxml_jsonl.py` | 输出 Hayabusa v4 `-J` 扁平 JSONL（`@timestamp`/`Hostname`/`Channel`/`EventID`/`RecordNumber`/`SourceName` + `EventData`），供 `hayabusa dfir-timeline -J -t jsonl -p super-verbose` 使用并对接 Takajo；支持 `--index-out` 输出 `(Computer, Channel, RecordID) -> event_id` 回查索引（Hayabusa 仅面向 Windows 事件日志） |
| **RSigma** | `winxml` | `ndjson` | `rsigma_winxml_ndjson.py` | XML 转扁平 NDJSON，统一 UTC `@timestamp` 与 `event_id`，默认按 UTC 时间升序排列以满足关联规则要求 |
| **RSigma** | `zeek_json` | `ndjson` | `rsigma_zeek_json_ndjson.py` | 保留原生数组结构与点分/下划线双字段，转换 `ts` -> UTC `@timestamp`，注入 `event_id` 并按 UTC 排序 |
| **RSigma** | `ecar_json` | `ndjson` | `rsigma_ecar_json_ndjson.py` | 转换 `timestamp_ms` -> UTC `@timestamp`，展开 Sigma 常用字段并保留 `properties`，按 UTC 排序 |
| **RSigma** | `syslog` | `ndjson` | `rsigma_syslog_ndjson.py` | 结构化 RFC 5424 并注入 `event_id` 与 UTC `@timestamp`，按 UTC 排序 |
| **RSigma** | `web_access` | `ndjson` | `rsigma_web_access_ndjson.py` | 结构化 Web 访问日志为 Sigma `webserver` NDJSON，按 UTC 排序 |
| **RSigma** | `bash_history` | `ndjson` | `rsigma_bash_history_ndjson.py` | 将两行式 bash_history 转为单行 NDJSON，按 UTC 排序 |
| **Chainsaw** | `winxml` | `json` | `chainsaw_winxml_json.py` | 输出 JSON 数组（`.json`），兼容 `mappings/sigma-event-logs-json.yml`（`Provider`/`TimeCreated` 为字符串 + `*_attributes`），附带 `event_id`/`raw_id` |
| **Chainsaw** | `zeek_json` | `json` | `chainsaw_zeek_json_json.py` | 输出 JSON 数组（`.json`），补充 ISO-8601 `timestamp`、`@timestamp`、`zeek_log_type`、`event_id`（配合 `configs/chainsaw_custom_mapping.yml`） |
| **Chainsaw** | `ecar_json` | `json` | `chainsaw_ecar_json_json.py` | 输出 JSON 数组（`.json`），补充 ISO-8601 `timestamp` 与 Sigma 扁平字段（配合 `configs/chainsaw_custom_mapping.yml`） |
| **Chainsaw** | `syslog` | `json` | `chainsaw_syslog_json.py` | 输出结构化 Syslog JSON 数组（`.json`） |
| **Chainsaw** | `web_access` | `json` | `chainsaw_web_access_json.py` | 输出结构化 Web 访问日志 JSON 数组（`.json`） |
| **Chainsaw** | `bash_history` | `json` | `chainsaw_bash_history_json.py` | 输出结构化 bash_history JSON 数组（`.json`） |

> **关于 `Takajo` 与 `pySigma` 的说明（对照 `日志.md`）：**
> - **Takajo**：仅消费上游 **Hayabusa** 生成的 JSONL 时间线（`hayabusa json-timeline -J -L -p super-verbose`），不直接读原始日志。上游流程为 `winxml` → `hayabusa_winxml_jsonl.py` → `hayabusa` → `takajo`。
> - **pySigma**：纯静态规则解析/校验/多后端转换库，输入为 Sigma YAML 规则与 Processing Pipeline，不直接消费日志数据。

---

## 三、环境管理与运行示例

```bash
# 同步虚拟环境（已通过 uv 初始化，包含 lxml / orjson / pyyaml / python-dateutil）
uv sync

# 1. Zircolite 示例（支持单文件、多文件或整个 log_example 目录自动过滤）
uv run zircolite_winxml_jsonl.py -i log_example -o out/zircolite/windows.jsonl --case-id case01
uv run zircolite_zeek_json_jsonl.py -i log_example -o out/zircolite/zeek.jsonl --case-id case01
uv run zircolite_ecar_json_jsonl.py -i log_example/ecar.json -o out/zircolite/ecar.jsonl --case-id case01
uv run zircolite_syslog_jsonl.py -i log_example/syslog.log -o out/zircolite/syslog.jsonl --case-id case01
uv run zircolite_web_access_jsonl.py -i log_example/web_access.log -o out/zircolite/web_access.jsonl --case-id case01
uv run zircolite_bash_history_jsonl.py -i log_example/sarah.oconnell.bash_history -o out/zircolite/bash_history.jsonl --case-id case01

# 2. Hayabusa 示例（附带生成 Computer+Channel+RecordID -> event_id 回查索引）
uv run hayabusa_winxml_jsonl.py -i log_example -o out/hayabusa/windows_evtx.jsonl \
  --index-out out/hayabusa/windows_event_id_index.jsonl --case-id case01

# 3. RSigma 示例（默认按 @timestamp UTC 升序排序，可直接用于 Sigma v2 关联规则）
uv run rsigma_winxml_ndjson.py -i log_example -o out/rsigma/windows.ndjson --case-id case01
uv run rsigma_zeek_json_ndjson.py -i log_example -o out/rsigma/zeek.ndjson --case-id case01
uv run rsigma_ecar_json_ndjson.py -i log_example/ecar.json -o out/rsigma/ecar.ndjson --case-id case01
uv run rsigma_syslog_ndjson.py -i log_example/syslog.log -o out/rsigma/syslog.ndjson --case-id case01
uv run rsigma_web_access_ndjson.py -i log_example/web_access.log -o out/rsigma/web_access.ndjson --case-id case01
uv run rsigma_bash_history_ndjson.py -i log_example/sarah.oconnell.bash_history -o out/rsigma/bash_history.ndjson --case-id case01

# 4. Chainsaw 示例（Chainsaw 2.18 `kind: json` 要求输出为 .json 数组格式）
uv run chainsaw_winxml_json.py -i log_example -o out/chainsaw/windows.json --case-id case01
uv run chainsaw_zeek_json_json.py -i log_example -o out/chainsaw/zeek.json --case-id case01
uv run chainsaw_ecar_json_json.py -i log_example/ecar.json -o out/chainsaw/ecar.json --case-id case01
uv run chainsaw_syslog_json.py -i log_example/syslog.log -o out/chainsaw/syslog.json --case-id case01
uv run chainsaw_web_access_json.py -i log_example/web_access.log -o out/chainsaw/web_access.json --case-id case01
uv run chainsaw_bash_history_json.py -i log_example/sarah.oconnell.bash_history -o out/chainsaw/bash_history.json --case-id case01
```

## 四、配套配置参考

- `configs/zircolite_config.yaml`：Zircolite 扁平化映射与 `event_id` 保留配置参考
- `configs/rsigma_pipeline.yml`：RSigma `@timestamp` 与关联证据保全（`correlation_event_mode: full`）Pipeline 参考
- `configs/chainsaw_custom_mapping.yml`：Chainsaw 非 Windows 自定义 JSONL 映射参考
