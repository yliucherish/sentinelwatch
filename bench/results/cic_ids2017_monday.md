# 基准评测：CIC-IDS2017 Monday-WorkingHours（2017-07-03，零攻击的完整工作日）

- PCAP：`Monday-WorkingHours.pcap`（10.1 GB，时间跨度 2017-07-03 19:57:58 ~ 2017-07-04 04:01:27）
- 数据来源：https://cicresearch.ca/CICDataset/CIC-IDS-2017/ → PCAPs/Monday-WorkingHours.pcap（实际为 pcapng，10,822,507,416 字节）
- 标注口径：`all-benign` —— 本文件不含攻击时间窗，全部请求标为「应放行」。**这份数据只用于测误报率与吞吐，不产出检出率**
- 备注：周一这一天**根本没有任何攻击**（不是『攻击不产生 HTTP 请求』，而是完全没有攻击段），官方 flow 标签里 529,918 条全是 BENIGN。所以它比周二更适合做误报率的独立佐证：周二虽然按 HTTP 请求粒度也是纯良性，但同一份抓包里确实存在 FTP/SSH 爆破，措辞上需要额外解释；周一不用。本仓库只还原 HTTP 请求，故以请求为分母。

> ⚠️ 数据集标签通常是**按流**打的，本工具产出的是**按请求**的事件。两者粒度不同，所以本报告不使用数据集自带的 flow 标签，而是用「时间窗 + 攻击源 IP」这个显式口径对齐。**口径写在上面，别人可以照着复核**——这是这份报告能被采信的前提。

## 混淆矩阵（逐请求，签名规则）

| | 判定为攻击 | 判定为正常 |
|---|---|---|
| **标注为攻击** | TP 0 | FN 0 |
| **标注为正常** | FP 3 | TN 54729 |

## 三个数

| 指标 | 值 | 说明 |
|---|---|---|
| 检出率（Recall） | — | 本数据集无标注攻击请求，检出率无定义 |
| 误报率（FPR） | **0.0055%** | 3/54732 条正常请求被误判 |
| 精确率（Precision） | 0.00% | 报出来的告警里多少是真的 |
| 吞吐 | **91.72 MB/s**，464 请求/s | 单线程，解析 + 检测合计 118.0s |

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

- 落在攻击时间窗内、但源 IP 不是攻击源的请求：**0 条**（占全部 54732 条的 0.00%）

  这类请求被记为「应放行」。它们可能是同网段的正常用户，也可能是数据集按 flow 标注导致的漏标。**把它印出来而不是藏起来**，是因为它直接决定了误报率的分母是否干净——读的人有权知道。
