# 工具交付验收记录

## 运行环境

实测 Windows 原生环境，Python 3.11.4、NumPy 1.26.4、SciPy 1.13.1、jsonschema 4.23.0、LangGraph 1.2.24、langchain-core 1.8.5、pytest 9.2.0。完整依赖见 `requirements-tested.txt`。未宣称已完成 Linux/WSL 实测。

标准隔离构建下 `pip install --no-deps -e .` 成功。联调入口 `python tools/smoke.py` 无需任何模型密钥，禁用外部追踪，使用纯合成资源和真实 LangGraph ToolNode。

## 协议与集成测试

13项pytest测试全部通过，覆盖：

- COPOD与融合两份清单的成功、分页、空结果、参数类型错误、保留参数拒绝、越界物理ID。
- 资源内容不合法、空记录资源。
- 超时回收、非零退出、stdout意外打印、响应ID错误、输出Schema错误、超过1 MiB。
- 重复证据拒绝、缺失可执行程序的START_ERROR。
- 异步并行调用：ToolMessage按tool_call_id关联，进程request_id各不相同；公开Schema只有k/offset/limit。

测试代码在 `tests/test_screening_tools.py`，可单独运行 `python -m pytest -q tests/test_screening_tools.py`。

## 本机兼容性回归

在仓库外的私有目录，以既有原始日志及中性定位索引生成特征，用一个完整留出场景和另两个独立参考场景执行回归。两种方法前10000名的物理ID、顺序及分数均与此前冻结版本完全相同。

这验证本次封装没有改变已检查场景的排序语义，不是重新开展检测成绩实验，也不能证明新场景泛化。该私有回归仅检查一个留出场景，未宣称重新验证全部留出折。真实日志、标注、物理ID、特征文件、候选列表和本机回归脚本均不在仓库中；公开仓库只保留这一不含样例的结论。

## 边界

工具会在内存中估计参考统计，不是外部预训练模型。程序不读取答案，不保存模型，不写调用资源。操作系统只读权限、资源快照、答案隔离及私有追踪配置由宿主部署方负责；应用协议不提供沙箱保证。候选分数不是恶意概率，也不是最终比赛输出。
