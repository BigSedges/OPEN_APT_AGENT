### 一、主机与终端日志（5 种）

| 日志文件 / 类型 | 格式 | 来源主机 | 说明 |
| --- | --- | --- | --- |
| **`ecar.json`** | JSON | 所有 Windows & Linux 主机 | 跨平台终端遥测日志（常见于 DARPA OpTC / eCAR 格式，记录进程、文件、网络连接等事件） |
| **`windows_event_security.xml`** | XML | 所有 Windows 主机（DC/FS/WEB/MAIL/WKS） | Windows 安全事件日志（登录、权限、审计等） |
| **`windows_event_sysmon.xml`** | XML | 所有 Windows 主机 | Windows Sysmon 监控日志（进程创建、网络连接、注册表与文件变更等） |
| **`syslog.log`** | 纯文本 | Linux 主机（`APP-LNX-02`、`DB-01`） | Linux 系统日志 |
| **`*.bash_history`** | 纯文本 | Linux 主机（`bash_history/` 子目录下） | 用户 Shell 命令历史（如 `sarah.oconnell`、`priya.patel`） |

### 二、应用服务日志（1 种）

| 日志文件 / 类型 | 格式 | 来源主机 | 说明 |
| --- | --- | --- | --- |
| **`web_access.log`** | 纯文本 | `WEB-01.example.local` | Web 服务器访问日志 |

### 三、网络流量传感器日志（10 种，均为典型 Zeek 日志）

全部位于 `SENSOR-NET-01` 目录下，均为 JSON 格式：

* **`conn.json`**：TCP/UDP/ICMP 网络连接记录
* **`dns.json`**：DNS 域名解析请求与响应
* **`http.json`**：HTTP 协议请求与响应
* **`ssl.json`**：SSL/TLS 加密连接握手信息
* **`x509.json`**：TLS 流量中提取的 X.509 数字证书信息
* **`ocsp.json`**：OCSP 证书状态在线查询记录
* **`dhcp.json`**：DHCP IP 地址分配记录
* **`files.json`**：网络流量中传输的文件元数据（哈希、MIME 类型等）
* **`pe.json`**：从流量中识别出的 Windows PE 可执行文件头信息
* **`smtp.json`**：SMTP 邮件传输协议日志

---
