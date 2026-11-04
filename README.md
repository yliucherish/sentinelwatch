# SentinelWatch — 主机日志审计与入侵检测平台

[![CI](https://github.com/yliucherish/sentinelwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/yliucherish/sentinelwatch/actions/workflows/ci.yml)

> 基于 Python 标准库的轻量级入侵检测平台：**日志 + 流量双数据源**——
> 暴力破解检测、文件完整性监控（FIM）、PCAP 流量还原与 HTTP 层攻击检测、
> 告警聚合降噪与可视化看板。
>
> **本工具仅用于分析你有权查看的日志/流量与你自己的主机。未授权部署/监控属违法行为。**

## 核心能力

| 模块 | 能力 | 设计要点（面试可讲） |
|---|---|---|
| 采集解析 | auth.log 领域解析 + 任意应用日志保底解析 + **PCAP 流量还原（v1.2）** | 两层分工：领域解析器给结构化字段（user/ip/port），保底解析器不丢任何行——覆盖率优先，真实 SIEM 采集层的标准分层 |
| 流量检测（v1.2） | 手写 libpcap 解析 → TCP 重组 → HTTP 还原 → 归一化 → 复用规则引擎 | **检测特征与数据源解耦**：三种采集器产出同一种事件模型，规则/存储/看板/报告一行不改就能吃流量。手写 pcap 解析不引 scapy（3 种链路类型、大小端、纳秒精度、乱序重组） |
| 规则引擎 | YAML 声明式规则 + 滑动窗口 + 阈值判定 + **签名匹配** | **新增检测场景 = 加一个 YAML 文件，不改代码**；阈值检测抓行为模式（爆破），签名匹配抓已知攻击特征（Log4Shell 载荷）——双模并存，参照 osquery/Wazuh + Suricata 的分工 |
| FIM | 目录 SHA256 基线 + added/modified/deleted 检测 | **哈希而非 mtime**（`touch` 可伪造 mtime，伪造不了 SHA256）；基线必须在监控树外（CLI 有防护） |
| 威胁情报（v1.1） | IOC 匹配：IP / CIDR / 域名（含子域）/ 文件哈希 / URL 片段 | **情报与规则分离**：规则描述"行为模式"（相对稳定、要人工调），情报描述"已知恶意实体"（天天变、可直接订阅）。命中**按 IOC 聚合成一条告警 + 命中次数**——一次爆破里同一恶名 IP 出现几十次，不聚合就是几十条重复告警。产出复用 Alert 模型，看板/报告/抑制器**零改动** |
| 告警聚合 | 按 (源 IP, 时间窗) 聚合成 Incident | 告警降噪 + **聚合不丢成员**（可解释性是蓝队工具的公信力基础） |
| Web 看板 | 告警时间线折线图 + TOP 源 IP 柱状图 + Incident 视图 | **零第三方依赖**：stdlib http.server + vanilla SVG；内网/隔离环境可演示 |
| 报告导出 | 一键生成独立 HTML 安全报告（服务端 SVG 图表） | 看板是"实时态势"，报告是"事后交付"——同一份 DB 两种消费形态；`@media print` 打印即存 PDF，不引 reportlab |
| 存储 | SQLite 单文件（events + alerts 双表） | 事件可回溯（"这条告警基于哪些事件"）；(ip, ts) 联合索引支撑窗口查询 |

内置检测规则（`rules/` 目录，全部 YAML 声明式）：

| 规则 | 判据 | 级别 |
|---|---|---|
| SSH 暴力破解 | 阈值：同 IP 5 分钟失败 ≥5 次 | high |
| SSH 用户名枚举 | 阈值：同 IP 5 分钟 Invalid user ≥5 次 | medium |
| Log4Shell JNDI 载荷 | 签名：日志含 `${jndi:`（CVE-2021-44228） | critical |
| Log4Shell 混淆变体 | 签名：`${lower:j` / `${::-j` 等嵌套绕过 | high |
| Log4Shell JNDI 触达 | 签名：`com.sun.jndi.ldap.LdapCtx@` 残留（JNDI 查询已发生） | high |
| Log4Shell 反序列化触达 | 签名：`com.sun.rowset.JdbcRowSetImpl@` 残留（序列化字节流已被还原） | high |
| Fastjson JdbcRowSetImpl 载荷 | 签名：`@type` + `com.sun.rowset.JdbcRowSetImpl` | critical |
| Fastjson autoType 缓存绕过 | 签名：`@type` 指向 `java.lang.Class`（1.2.25–1.2.47） | critical |
| Fastjson expectClass 绕过 | 签名：`@type` 指向 `java.lang.AutoCloseable` | critical |
| Fastjson JNDI 地址兜底 | 签名：输入含 `ldap://` / `rmi://` | high |
| 流量侧 Log4Shell（v1.2） | 签名：HTTP 请求（归一化后）含 `${jndi:` | critical |
| 流量侧 Fastjson autoType（v1.2） | 签名：body 含 `@type` + 已知利用链类 | critical |
| 流量侧 WebShell 落地（v1.2） | 签名：body 含 `eval($_POST` / `Runtime.exec(` | critical |

## 快速开始

```bash
# 无需安装任何依赖（Python 3.10+；PyYAML 仅规则加载需要）
pip install pyyaml

# 1. 导入日志 → 规则检测 → 告警入库
python cli.py import --log tests/sample_auth.log --db sentinelwatch.db --reset

# 1.5 叠加威胁情报匹配（可选）：命中恶名 IP / 域名 / 哈希 / URL 时产出 IOC-* 告警
python cli.py import --log tests/sample_auth.log --db sentinelwatch.db --reset \
    --iocs tests/sample_intel.csv
# → 规则层抓到"5 次失败登录"，情报层补充"这个 IP 是已知演练网段"，
#   两条告警互补而不是重复；同一 IOC 只产 1 条（命中次数写进 event_count）

# 1.6 流量检测（v1.2）：直接吃 PCAP，与日志进同一张表、同一套规则引擎
python cli.py traffic --pcap tests/fixtures/traffic_demo.pcap --db sentinelwatch.db
# → 8 个包 → 还原 5 条 HTTP 请求 → 3 条 CRITICAL（Log4Shell / Fastjson / WebShell）
#   演示 PCAP 由 tools/pcapgen.py 合成（校验和正确，Wireshark 可直接打开）：
#   python -m tools.pcapgen out.pcap

# 2. 文件完整性监控：先建基线，改动文件后再扫一次
python cli.py fim --dir /path/to/watch --baseline /tmp/fim_baseline.json
#    （修改/新增/删除文件后重复同一命令，即产生 FIM 告警）

# 3. 启动看板（默认仅绑 127.0.0.1）
python cli.py serve --db sentinelwatch.db --port 8080
#    浏览器打开 http://127.0.0.1:8080

# 4. 导出 HTML 告警报告（浏览器 Ctrl+P 可另存为 PDF）
python cli.py report --db sentinelwatch.db --out report.html
```

**应用日志检测示例**（Log4Shell，样本攻击行取自 `cve-research/` 的真实复现捕获）：

```bash
python cli.py import --log tests/sample_app.log --format app --db log4shell.db --reset
# → 2 条 CRITICAL（${jndi: 载荷）+ 2 条 HIGH（JNDI 查找/反序列化残留），正常行静默
```

内置样本：`tests/sample_auth.log`（22 条手工构造事件：暴力突发 / 慢速尝试 /
用户名枚举 / 正常流量 / CRON 脏行）。导入后预期 2 条告警：
**SSH 暴力破解（HIGH，203.0.113.9）** 与 **SSH 用户名枚举（MEDIUM，192.0.2.66）**，
慢速尝试 IP（198.51.100.7，跨 15 分钟 3 次）正确不告警。

报告导出效果见 [`reports/demo_report.html`](reports/demo_report.html)（由样本日志一键生成）。

## 架构与数据链路

![架构图](docs/architecture.svg)

```mermaid
flowchart LR
    A[auth.log / 应用日志] --> B[collectors/<br/>auth_log.py 领域解析 + app_log.py 保底解析]
    P[PCAP 抓包文件] --> Q[collectors/pcap.py<br/>libpcap 解析 + TCP 重组<br/>+ HTTP 还原 + 归一化]
    C[被监控目录] --> D[fim.py<br/>SHA256 基线 + 三类变更]
    B --> E[engine/detector.py<br/>YAML 规则 + 滑动窗口 + 签名匹配]
    Q --> E
    I2[威胁情报<br/>CSV / JSON / 文本] --> K[intel/<br/>IOC 匹配 · 按 IOC 聚合]
    B --> K
    Q --> K
    E --> F[(storage.py<br/>SQLite: events + alerts)]
    K --> F
    D --> F
    F -->|只读| G[web/server.py<br/>聚合 Incident + /api/data]
    G --> H[dashboard.html<br/>看板 · vanilla SVG]
    G --> I[report.py<br/>报告导出 · 服务端 SVG]
    I --> J[report.html<br/>交付物 · 打印即 PDF]
```

**三条采集链路汇进同一个事件表**——这是 v1.2 最重要的结构变化：
日志（`app_log`）、认证日志（`failed_password` 等）、流量（`http_request`）
产出的都是同一组字段的 `Event`，所以规则、存储、看板、报告零改动。
新增数据源的成本从"改五处"降到"加一个采集器 + 一份规则文件"。

**为什么事件与告警分表**：告警必须可解释、可取证——每条告警都能回溯到原始事件。
这是审计类系统的基本要求，也是与"玩具项目"的分水岭。

**为什么聚合与抑制分开**：引擎内的 suppress 解决"同一条规则的重复告警"；
`suppressor.py` 解决"不同规则的关联呈现"（一次暴力破解同时触发暴力破解 +
用户名枚举两条规则，应呈现为一个 Incident 而非两条）。

**为什么看板与报告是两份出口**：看板面向"正在值班的人"（实时、可交互、
按时间倒序）；报告面向"事后复盘/交付"（静态、可打印、按严重度排序）。
同一份 DB、同一套聚合（`report.py` 直接复用 `web/server.py` 的
`build_api_payload`——单一定义源，避免两套聚合各漂各的）。

### 威胁情报层（v1.1 新增）

规则层回答「这个行为像不像攻击」，情报层回答「这个实体是不是已知的坏东西」。
两者是正交判据，所以做成两个模块、产同一种告警。

| IOC 类型 | 匹配方式 |
|---|---|
| `ip` | 精确匹配日志中的 IP 字面量（IPv4 / IPv6） |
| `cidr` | 网段包含判断（`ip in network`） |
| `domain` | **后缀边界匹配**：`a.b.evil.com` 命中 `evil.com`，但 `notevil.com` 不命中 |
| `hash` | MD5(32) / SHA1(40) / SHA256(64)，按长度校验后再比 |
| `url` | 子串包含（用于匹配 C2 落地页路径） |

情报文件支持 CSV / JSON / 纯文本，`kind` 可省略（按值的形态自动推断）：

```csv
value,kind,source,note
45.9.148.37,ip,abuse.ch Feodo,Emotet C2
203.0.113.0/24,cidr,自建,演练网段
```

三个关键决策（都有对应测试）：

1. **按 IOC 聚合**：一次爆破里同一恶名 IP 出现 10 次，只产 1 条告警 +
   `命中次数=10`，窗口覆盖首次到末次命中。不聚合就是 10 条重复告警——
   实测第一次跑出来 12 条告警，8 条是同一个 IOC 重复喊；
2. **复用 Alert 模型**：IOC 告警直接进同一张 `alerts` 表，看板 / HTML 报告 /
   抑制器**零改动**——这是"不重复建模"换来的收益；
3. **误报优先控制**：域名后缀边界、时间格式 `12:34:56` 不当 IPv6、CIDR 严格边界，
   每一条都有独立的真阴性测试（`test_no_false_positive_on_benign_logs`）。

## 流量检测层（v1.2 新增）

### 为什么日志不够

同一场攻击，在日志和流量里留下的痕迹不一样，各有盲区：

| 攻击场景 | 日志侧 | 流量侧 |
|---|---|---|
| Log4Shell 载荷 | 只有应用真的用 log4j 打了这条日志才可见 | 请求头 / URL 里的载荷必现 |
| 被上游 WAF 拦下的请求 | **看不到**（请求没到应用） | 看得到（拦在网络层之前） |
| 日志被截断 / 转义 / 丢弃 | 看不到原文 | 看得到原始字节 |
| WebShell 落地请求 | **看不到**（写入的内容不进日志） | 看得到 POST body |
| 主机行为（爆破、文件篡改） | 看得到 | 看不到 |

所以真实 IDS 是双数据源。本项目把流量也变成**同一种事件模型**：

```
PCAP ──▶ libpcap 解析 ──▶ TCP 重组 ──▶ HTTP 还原 ──▶ 归一化 ──▶ 规则引擎 ──▶ 同一种 Alert
        (3 种链路类型)   (乱序/重传)   (按 Content-Length)  (解码+小写)   (15 条规则)   (看板/报告)
```

### 四个值得讲的设计决策

1. **手写 libpcap 解析，不引 scapy**：支持 Ethernet(1) / Raw IP(101) / Linux SLL(113)
   三种链路类型（`tcpdump -i any` 产出的是 SLL，只支持 Ethernet 会直接踩坑）、
   大小端 magic、微秒/纳秒精度、802.1Q VLAN 标签。省一个依赖的收益比想象中大——
   安全工具自身加载第三方库就是供应链攻击面。
2. **TCP 重组必须处理乱序**：攻击者把载荷拆成两个包本身就是一种绕过。
   实现上"先收齐再按 seq 拼"，而不是边收边吐——因为先到的可能是**后半段**，
   以首包为基准做流式拼接会把前半段永远丢掉（有专门的乱序测试守着）。
3. **判据与证据分离**：每个事件同时带 `raw`（原始字节，取证用）和
   `normalized`（URL 解码到不动点 + 转小写，签名匹配用）。
   `${jndi:` 可以写成 `%24%7Bjndi%3A`（URL 编码）、`${JNDI:`（大小写）、
   甚至双重编码——只对原文匹配，一个 `%24` 就绕过。**判据可以归一化，证据不能改写。**
4. **规则分文件、签名词汇共用**：`log4shell.yaml` 吃 `app_log`，
   `http_traffic.yaml` 吃 `http_request`，但判据是同一套——这就是
   "检测特征不绑定数据源"。新增数据源 = 一个采集器 + 一份规则文件，引擎零改动。

### 已知限制（写在明面上）

| 限制 | 原因 | 影响 |
|---|---|---|
| 只支持未加密 HTTP/1.x | HTTPS 需要密钥/解密代理 | 生产环境大部分流量看不到（真实 IDS 同样要解密方案） |
| 不支持 chunked / gzip body | 按 Content-Length 取体 | 少数 API 会漏（已列 TODO） |
| 不做完整 TCP 状态机 | 离线 PCAP 分析不需要跟踪握手/挥手 | 在线旁路抓包需补状态机 |
| IPv4 only | 未实现 IPv6 解析 | 双栈环境会漏 IPv6 流量 |

**这些限制不是"没做完"，而是"边界说清楚"**——面试官更在意你知不知道自己
方案的能力边界，而不是你有没有把全部功能都写完。

> 与 [BypassLab](https://github.com/yliucherish/bypasslab) 的关系：BypassLab 是
> "造 WAF 并自己打"，本层是"在流量里抓这些攻击"。前者的归一化管道思想
> （解码到不动点再匹配）与这里的 `normalize()` 是同一个判断：
> **绕过与检测的对抗，本质上是"谁先把对方的表示形式规范化"**。

## 测试

```bash
pytest tests/ -v     # 88 个用例
```

- `test_engine.py`（8 个）：解析 / 规则加载 / 阈值与窗口边界 / 存储闭环
- `test_fim_suppressor.py`（9 个）：FIM 三类变更 + 排除规则 + 流式哈希正确性；
  抑制器同 IP 聚合 / 超窗拆分 / 严重度取最高 / 主机侧分组 / 排序
- `test_report.py`（10 个）：报告全链路 / XSS 转义（恶意告警字段不得逃逸）/
  服务端 SVG 图表 / 空库降级 / 零外部引用 / 打印适配 / CLI 子命令
- `test_log4shell_rules.py`（11 个）：通用日志解析器（时间戳/IP/保底不丢行）/
  签名匹配算子（AND/OR）/ Log4Shell 四规则端到端检出 / 静默与 IP 归因 / CLI
- `test_fastjson_rules.py`（12 个）：Fastjson 六规则端到端 / 三种绕过手法
  逐行精确断言 / 静默语义（只拿正常业务行跑规则断言零告警）/ IP 归因 / CLI
- `test_ioc.py`（13 个）：五类 IOC 匹配 / 域名后缀边界 / 聚合与命中次数 /
  真阴性（时间戳不当 IPv6 等）
- `test_pcap.py`（17 个）：PCAP 解析（大小端 / 纳秒 / 三种链路类型 / 截断）/
  TCP 乱序重组 / HTTP keep-alive 多条请求 / 服务端响应与 UDP 不产生事件 /
  URL 编码与大小写变形检出 / 正常流量零告警 / 与存储层字段兼容

**签名匹配（v1.0）判据语义**：`raw_contains` 列表全部子串都要出现（AND，
收窄匹配）；`raw_contains_any` 任一出现即匹配（OR，同族变体）。两种算子
显式区分——安全规则的匹配条件必须可预测，不靠约定俗成。

## 与 Wazuh / osquery 的关系（致敬与差异）

| | SentinelWatch | Wazuh |
|---|---|---|
| 部署 | 单文件 + SQLite，拷贝即用 | Agent + Manager + Elastic 栈 |
| 数据源 | 日志 + FIM + **PCAP 流量**（v1.2，自带解析与 HTTP 还原） | 日志 + 审计 + 漏洞扫描（流量侧通常另接 Suricata/Zeek 的告警） |
| 规则 | YAML 声明式，单目录加载 | XML 规则 + 解码器体系 |
| 实时性 | 文件导入（实时 agent 列为 v1.5） | 实时采集 |
| 定位 | 学习/演示/小规模主机自查 | 生产级企业部署 |

设计思想（基线 + 声明式规则 + 滑动窗口 + 告警聚合）向 osquery 与 Wazuh 致敬，
工程规模刻意保持轻量——**这个项目的目标是"把 SIEM 的核心链路完整讲清楚"，
而不是再造一个 Wazuh**。

## 技术博客

- 《我用 Python 给自己写了个迷你 osquery：主机入侵检测实践》——三个设计决策（双采集器分层、阈值+签名双模、告警聚合）与各自的取舍

见 [`blog/`](blog/) 目录。

## 免责声明

本工具仅供学习交流和授权环境下的安全分析使用。对未授权主机进行日志收集、
文件监控属于违法行为，使用者需自行承担法律责任。
