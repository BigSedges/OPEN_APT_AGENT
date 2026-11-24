"""安全数据集日志类型定义与文件抽象模块"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class LogCategory(str, Enum):
    """日志来源大类。"""
    HOST = "host"        # 主机终端日志
    APP = "app"          # 应用服务日志
    NETWORK = "network"  # 网络传感器日志 (Zeek)


class LogFormat(str, Enum):
    """底层文件格式，用于决定调用哪类解析器。"""
    JSON = "json"
    XML = "xml"
    TEXT = "text"


class LogType(str, Enum):
    """具体日志类型。"""
    # 主机与终端
    ECAR = "ecar"
    WIN_SECURITY = "windows_event_security"
    WIN_SYSMON = "windows_event_sysmon"
    SYSLOG = "syslog"
    BASH_HISTORY = "bash_history"

    # 应用服务
    WEB_ACCESS = "web_access"

    # 网络流量 (Zeek)
    ZEEK_CONN = "conn"
    ZEEK_DNS = "dns"
    ZEEK_HTTP = "http"
    ZEEK_SSL = "ssl"
    ZEEK_X509 = "x509"
    ZEEK_OCSP = "ocsp"
    ZEEK_DHCP = "dhcp"
    ZEEK_FILES = "files"
    ZEEK_PE = "pe"
    ZEEK_SMTP = "smtp"

    @property
    def category(self) -> LogCategory:
        if self in {
            self.ECAR, self.WIN_SECURITY, self.WIN_SYSMON,
            self.SYSLOG, self.BASH_HISTORY,
        }:
            return LogCategory.HOST
        if self is self.WEB_ACCESS:
            return LogCategory.APP
        return LogCategory.NETWORK

    @property
    def file_format(self) -> LogFormat:
        if self in {self.WIN_SECURITY, self.WIN_SYSMON}:
            return LogFormat.XML
        if self in {self.SYSLOG, self.BASH_HISTORY, self.WEB_ACCESS}:
            return LogFormat.TEXT
        return LogFormat.JSON


# 精确文件名到枚举的映射
_FILENAME_TO_TYPE: dict[str, LogType] = {
    "ecar.json": LogType.ECAR,
    "windows_event_security.xml": LogType.WIN_SECURITY,
    "windows_event_sysmon.xml": LogType.WIN_SYSMON,
    "syslog.log": LogType.SYSLOG,
    "web_access.log": LogType.WEB_ACCESS,
    "conn.json": LogType.ZEEK_CONN,
    "dns.json": LogType.ZEEK_DNS,
    "http.json": LogType.ZEEK_HTTP,
    "ssl.json": LogType.ZEEK_SSL,
    "x509.json": LogType.ZEEK_X509,
    "ocsp.json": LogType.ZEEK_OCSP,
    "dhcp.json": LogType.ZEEK_DHCP,
    "files.json": LogType.ZEEK_FILES,
    "pe.json": LogType.ZEEK_PE,
    "smtp.json": LogType.ZEEK_SMTP,
}


@dataclass(frozen=True)
class LogFile:
    """表示磁盘上的单个日志文件及其上下文信息。"""
    path: Path
    log_type: LogType
    scenario: str  # 如 "uat4356", "2024-05-30-apt28"
    host: str      # 如 "APP-LNX-02.example.local", "SENSOR-NET-01"

    @property
    def category(self) -> LogCategory:
        return self.log_type.category

    @property
    def file_format(self) -> LogFormat:
        return self.log_type.file_format

    @classmethod
    def from_path(cls, path: Path, scenario: str, host: str) -> Optional["LogFile"]:
        """根据路径自动识别日志类型；非日志文件（如 Label.json）返回 None。"""
        name = path.name
        if name.endswith(".bash_history"):
            log_type = LogType.BASH_HISTORY
        else:
            log_type = _FILENAME_TO_TYPE.get(name)

        if log_type is None:
            return None
        return cls(path=path, log_type=log_type, scenario=scenario, host=host)