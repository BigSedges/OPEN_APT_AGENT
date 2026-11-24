# OPEN_APT_AGENT

面向 APT 防守场景的日志分析智能体。当前提交定义 Python 项目结构、事件模型和各阶段接口，供后续实现。

## 模块

- `apt_agent/models.py` 定义统一事件、初筛发现和关联案件。发现通过事件 ID 引用日志证据。
- `apt_agent/parsing.py` 定义日志解析接口。不同日志格式可分别实现适配器。
- `apt_agent/detection.py` 定义规则检测与统计检测共用的初筛接口。
- `apt_agent/correlation.py` 定义告警关联接口，将初筛发现和对应证据组成案件。
- `apt_agent/retrieval.py` 定义 RAG 知识库索引和检索接口，检索结果携带来源和片段编号。
- `apt_agent/analysis.py` 定义供 LLM 适配器实现的分析接口，接收案件和检索片段。
- `apt_agent/pipeline.py` 定义流水线契约，`apt_agent/config.py` 定义初始配置。
- `tests/` 预留后续单元测试位置。
- `apt_agent/log_type.py` 日志类型定义模块，方便工具选择以及Agent任务编排。

## 开发入口

项目元数据声明 Python 3.9+，当前阶段无第三方依赖。接入各模块实现后，由流水线按解析、初筛、关联、检索、分析的顺序编排。当前版本供代码协作使用，运行入口留待实现阶段添加。
