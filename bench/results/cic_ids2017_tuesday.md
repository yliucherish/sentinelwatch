# 基准评测：CIC-IDS2017 Tuesday-WorkingHours（2017-07-04，纯 HTTP 良性语料）

- PCAP：`data\Tuesday-WorkingHours.pcap`（10.3 GB，时间跨度 2017-07-04 19:56:02 ~ 2017-07-05 04:00:30）
- 数据来源：https://cicresearch.ca/CICDataset/CIC-IDS-2017/ → PCAPs/Tuesday-WorkingHours.pcap（实际为 pcapng，11,048,283,608 字节）
- 标注口径：`all-benign` —— 本文件不含攻击时间窗，全部请求标为「应放行」。**这份数据只用于测误报率与吞吐，不产出检出率**
- 备注：周二这一天的攻击目标是 FTP(21) 与 SSH(22)，没有一条 HTTP 攻击。而本工具的流量采集器只还原 HTTP 请求，所以这一天在「按 HTTP 请求」的事件粒度下是**纯良性语料**：它测得出误报率和真实规模吞吐，测不出检出率。之所以仍然要跑它，是因为误报率必须由第三方语料给出——拿自己造的良性流量算误报率，等于自己出题自己答。检出率留给周四（Web 攻击段，见 cic_ids2017_thursday_web.json）。

> ⚠️ 数据集标签通常是**按流**打的，本工具产出的是**按请求**的事件。两者粒度不同，所以本报告不使用数据集自带的 flow 标签，而是用「时间窗 + 攻击源 IP」这个显式口径对齐。**口径写在上面，别人可以照着复核**——这是这份报告能被采信的前提。

## 混淆矩阵（逐请求，签名规则）

| | 判定为攻击 | 判定为正常 |
|---|---|---|
| **标注为攻击** | TP 0 | FN 0 |
| **标注为正常** | FP 0 | TN 48345 |

## 三个数

| 指标 | 值 | 说明 |
|---|---|---|
| 检出率（Recall） | — | 本数据集无标注攻击请求，检出率无定义 |
| 误报率（FPR） | **0.0000%** | 0/48345 条正常请求被误判 |
| 精确率（Precision） | — | 没有产生任何告警，精确率无定义 |
| 吞吐 | **81.49 MB/s**，357 请求/s | 单线程，解析 + 检测合计 135.6s |

## 分攻击类型

| 攻击类型 | 总数 | 检出 | 检出率 |
|---|---|---|---|
| （无标注为攻击的请求） | 0 | 0 | — |

## 参与判定的规则

只统计**签名规则**（单条请求即可判定），且只列 `event_types` 与本次数据（http_request）有交集的规则——只吃应用日志的规则对流量永不命中，列进来纯属误导。

阈值规则（窗口聚合）没有进混淆矩阵：一次爆破的 5 条失败请求无法逐条标注"哪条该告警"，粒度不同不能混算。

- `http-log4shell-jndi`（critical）— 流量侧 Log4Shell JNDI 注入（CVE-2021-44228）
- `http-fastjson-autotype`（critical）— 流量侧 Fastjson autoType 反序列化载荷
- `http-webshell-body-markers`（critical）— 流量侧 WebShell 落地特征
- `http-sqli-union-select`（critical）— 流量侧 SQL 注入（UNION 联合查询）
- `http-sqli-boolean-blind`（high）— 流量侧 SQL 注入（布尔盲注）
- `http-sqli-time-based`（high）— 流量侧 SQL 注入（时间盲注）
- `http-sqli-metadata-probe`（high）— 流量侧 SQL 注入（元数据/文件探测）
- `http-xss-script-injection`（high）— 流量侧 XSS（脚本标签注入）
- `http-xss-event-handler`（medium）— 流量侧 XSS（事件处理器注入）
- `http-path-traversal`（high）— 流量侧 路径遍历

## 标注灰色地带

- 落在攻击时间窗内、但源 IP 不是攻击源的请求：**0 条**（占全部 48345 条的 0.00%）

  这类请求被记为「应放行」。它们可能是同网段的正常用户，也可能是数据集按 flow 标注导致的漏标。**把它印出来而不是藏起来**，是因为它直接决定了误报率的分母是否干净——读的人有权知道。
