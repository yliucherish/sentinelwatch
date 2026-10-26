"""威胁情报（IOC）匹配层。

对外只暴露三样东西：
    IOCSet        —— 情报集合，支持 csv / json / 纯文本加载与匹配
    IOC           —— 单条情报
    match_events  —— 把事件流跑一遍情报，产出标准 Alert

用法：
    from intel import IOCSet, match_events

    iocs = IOCSet()
    iocs.load_file("intel/feodo.csv")
    alerts = match_events(events, iocs)
"""
from intel.ioc import (
    IOC,
    KIND_CIDR,
    KIND_DOMAIN,
    KIND_HASH,
    KIND_IP,
    KIND_URL,
    IOCSet,
    infer_kind,
)
from intel.matcher import match_events

__all__ = [
    "IOC",
    "IOCSet",
    "infer_kind",
    "match_events",
    "KIND_IP",
    "KIND_CIDR",
    "KIND_DOMAIN",
    "KIND_HASH",
    "KIND_URL",
]
