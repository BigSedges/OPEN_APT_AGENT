# 调查任务 RAG 本轮运行说明

根目录为 E:\APT_agent\rag-experiment。源码位于 work\OPEN_APT_AGENT，分支 codex/public-rag-quality。当前语料为 corpus-v1-candidate，正式冻结仍需解决质量报告列出的缺项。

运行前设置 APT_RAG_ROOT 为根目录，PYTHONPATH 为 work\OPEN_APT_AGENT，TEMP 和 TMP 为根目录下 tmp，HF_HOME 为 models\cache，HAYSTACK_TELEMETRY_ENABLED 为 false。

InvestigationQuery 支持 field_explanation、detection_prerequisites、technique_association、false_positives、follow_up。参数包含 question、filters、as_of、time_basis、mode、top_k 和 context_characters。filters 接受 platform、log_source、event_ids、attack_ids、source_family 和 source_version。缺失条件保持未知，时间缺失在指定截止条件时保守排除并记录数量。source_published_at 在尚未取得原始发布时间的记录中保持未知。

InvestigationRetriever 使用统一原文记录，先按元数据及时间确定允许片段，再交给检索器。JSON 记录保存查询、过滤、各通道排名、最终引用、上下文遗漏及失败原因。SHA-256 可发现记录变更，证明完整性仍需在外部保管可信摘要。verify_citation 检查存在性、正文哈希和来源版本。support_review 保持 unreviewed，人工需要逐项判断正文是否支持结论。外部正文作为不可信数据标记，模型提示词注入防护的端到端有效性待生成阶段测试。

本轮测试覆盖过滤、时间未知及排除、上下文预算、模型缺失、引用回查和记录篡改。尚未实现实际检索超时终止、自动语义支持判定或冲突解决。

切块比较工具 compare_chunking.py 对旧开发集的前 30 个可回答问题比较通用 800 字符且重叠 150 字符的切块与结构候选切块，记录排名和整块上下文预算溢出。该比较仅是助手草稿问题的结构检查，尚待必要条件完整性的独立人工标签。旧开发题的选择早于 tasks-v2 划分，跨版本复用时必须记录暴露情况。

新版 150 题草稿保存在 evaluation\tasks-v2，分配为字段 30、检测前提 35、技术关联 30、误报 20、跨语言 20、无法回答 15。主题分组后开发 60、测试 90。问题来自已有助手草稿重组，误报题的表达与必要回答要点仍需人工编辑和审核。

BGE-M3 性能探针为 models\probe.py，校验本地模型哈希后在固定的 200 片段上使用 CPU、batch_size=2、512 token 上限运行。该长度用于性能探针，报告记录实际截断数量。正式索引的长度和批量配置应由结构完整性与资源试验共同决定。

运行测试命令为 work\rag-venv\Scripts\python.exe -m unittest discover -s work\OPEN_APT_AGENT\tests -p test_investigation.py -v。语料检查命令为同一 Python 运行 apt_agent\knowledge\quality.py，切块检查运行 compare_chunking.py。全量向量、关系扩展、重排、公开事件和生成评测均待完成。

本轮执行结果已回收。调查接口在真实语料上验证得到 ok、time_filtered、context_incomplete 三种状态，并保存可校验的运行记录。针对性单元测试 3 项通过。

切块实验的通用配置生成 12078 个片段，其中 Sigma 7519 个片段中 1483 个同时包含 detection 与 condition。结构配置生成 5254 个片段，2481 条 Sigma 完整规则全部保留二者。该计数是结构完整性检查，尚未验证条件语义完整。30 个开发问题中，结构配置出现 3 次整块上下文预算遗漏，通用配置为 0。不能据此断言检索质量或选定正式配置。

BGE-M3 已下载并通过清单逐文件哈希检查。固定 200 片段 CPU 探针耗时 130.21 秒，1024 维，向量范数约为 1。4 CPU 线程、batch_size=2、512 token 上限下，32 条被截断。结束时进程 RSS 约 2.10 GB，该值为结束内存，未采集峰值。

源码提交 c0e7f93 为本轮初始提交，后续增加运行模型配置记录。语料冻结仍待解决缺失获取时间、未解析关系端点、重复审查和长 CAR 条目。已生成的草稿问题来自原语料标题模板，需改写、补充必要回答要点并独立标注后用于正式结论。AiSOC 设计按用户提供的静态审核结果作为本轮需求参考，本轮未重新运行 AiSOC。
