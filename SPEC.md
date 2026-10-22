# SentinelWatch 开发规格书（SPEC）

> 项目②：主机日志审计与入侵检测平台。定位：蓝队/安全运营方向的主打项目。
> 一句话介绍（简历用）："基于 Python 的轻量级主机入侵检测与日志审计平台，
> 实现暴力破解检测、文件完整性监控与可视化告警看板"。
> 状态：🟢 v1.0 已完成（检测引擎[阈值+签名双模] + FIM + 聚合抑制 + Web 看板 +
> 报告导出 + Log4Shell 检测规则；pytest 38/38 全绿；演示 GIF 为剩余可选项）。

## 1. 核心卖点（与"玩具项目"拉开差距的点）

- 检测逻辑参照 **osquery / Wazuh 的设计思想**（基线 + 规则引擎），README 中明确致敬与对比
- 规则引擎**声明式**（YAML 定义规则），而非硬编码 if-else——这是工程能力的体现
- 告警有**抑制与聚合**（同一 IP 10 次失败聚合为 1 条告警而非 10 条）

## 2. 技术栈

- 后端：Python 标准库（http.server）+ SQLite（**零第三方运行时依赖**，拷走即跑；
  FastAPI 原为备选，见 v0.2 选型说明）
- 前端：纯 HTML + vanilla JS + 内联 SVG 图表（单页可演示，无 CDN 依赖）
  **UI 配色：蓝白主色 + 紫色点缀（用户审美偏好，硬性要求）**
- 采集：解析 Linux `auth.log` / Windows 事件日志导出文件（不做实时 agent，先文件导入，
  实时采集列为 v1.5 增强）

## 3. 架构（v0.2 实际落地结构）

```
collectors/        # 日志解析器（两层分工，面试可讲）
  auth_log.py      # 领域解析：auth.log → failed/accepted/invalid_user/sudo
  app_log.py       # 保底解析（v1.0）：任意应用日志行 → app_log 事件，不丢行
rules/             # 声明式规则（YAML）
  brute_force.yaml # 阈值检测：同 IP 5 分钟内失败 ≥5 次 → high
  log4shell.yaml   # 签名检测（v1.0）：${jndi: 载荷 / 混淆变体 / JNDI 查找残留
engine/
  detector.py      # 规则引擎：滑动窗口 + 阈值 + 签名匹配（match 字段）+ 静默
fim.py             # 文件完整性监控：目录哈希基线 + 三类变更检测（顶层模块）
suppressor.py      # 告警聚合抑制：多规则 → Incident（跨规则关联）
storage.py         # SQLite：events + alerts 双表，(ip, ts) 联合索引
models.py          # AuthEvent / Alert dataclass（事件与告警分模型）
report.py          # 报告导出：build_report_data/render_html/export_report（v1.0）
web/
  server.py        # stdlib http.server：/api/data 一次算出全部聚合数据
  dashboard.html   # 看板：时间线折线 + TOP IP 柱状（vanilla SVG）+ Incident 视图
cli.py             # import / fim / serve / report 四个子命令
docs/
  architecture.svg # 架构图（蓝白紫主题）
reports/
  demo_report.html # 样本日志一键生成的演示报告
tests/
  sample_auth.log  # 22 条手工构造样本（暴力突发/慢速/枚举/正常/脏行）
  sample_app.log   # 10 条应用日志样本（攻击行取自 Log4Shell 复现真实捕获）
```

## 4. 任务清单

### v0.1（W4）
- [x] auth.log 解析器 + 暴力破解检测（滑动窗口）+ SQLite 存储
- [x] YAML 规则加载与引擎
- [x] 测试样本：`tests/sample_auth.log`（手工构造含暴力破解片段的日志）
  （验收：pytest 9/9 全绿；CLI 导入 22 条事件 → 2 条告警：
  暴力破解 HIGH + 用户名枚举 MEDIUM，慢速 IP 正确不告警）

### v0.2（W5）
- [x] 文件完整性监控（`fim.py`：目录 SHA256 基线 + added/modified/deleted 三类变更 +
  变更转 Alert 统一入库；排除规则；流式哈希；CLI 防护"基线放在监控目录内"的经典事故）
- [x] 告警聚合抑制器（`suppressor.py`：按 (source_ip, 时间窗) 聚合成 Incident，
  超窗拆分、严重度取最高、聚合不丢成员——告警降噪 + 可解释性）
- [x] 蓝白紫看板前端（`web/`：stdlib http.server 零依赖服务 + vanilla SVG 图表
  （告警时间线折线 + TOP 源 IP 柱状）+ 告警明细表 + Incident 聚合视图；
  配色蓝白主色 + 紫色点缀；`/api/data` 一次查询出全部聚合数据）
  > 技术选型说明：原计划 FastAPI + Chart.js CDN，实际改为**标准库 + 纯 SVG**——
  > ① 安全工具常在内网/隔离环境演示，CDN 抽风整个看板白屏；
  > ② 安全工具自身加载第三方 JS 是供应链攻击面；③ 零依赖"拷走即跑"。
  > 这个取舍本身是面试素材（安全场景下的依赖决策）。

### v1.0（W6）
- [x] 告警报告导出（`report.py`：`build_report_data` / `render_html` /
  `export_report` 三层分离；服务端静态 SVG 图表；`@media print` 打印即 PDF；
  复用 `web/server.py` 的聚合作单一定义源；CLI `report` 子命令；
  9 个测试：全链路 / XSS 转义 / 图表 / 空库降级 / 零外部引用 / 打印适配 / CLI）
- [x] 规则引擎签名匹配（`match` 字段：`raw_contains` AND / `raw_contains_any` OR，
  在原始日志行上做子串判定——从"纯阈值检测"升级为"阈值 + 签名"双模，
  真实 IDS 的标准形态；旧规则不带 match 完全向后兼容）
- [x] 通用日志采集器（`collectors/app_log.py`：保底解析任意应用日志行，
  与 auth_log.py 形成"领域解析 + 保底解析"两层分工；ISO/syslog 时间戳
  尽力提取、行内 IP 提取、不丢行）
- [x] Log4Shell 检测规则（`rules/log4shell.yaml` 4 条：${jndi: 载荷 →
  critical；混淆变体 ${lower:j/${::-j → high；JNDI 查找触达残留
  LdapCtx@ → high；反序列化触达残留 → high）——规则依据
  cve-research/CVE-2021-44228-log4shell/ 的复现实证编写，
  把项目①②③串成"攻击复现 → 检测落地"的闭环）
- [x] README 双语（README.md 中文 + README_EN.md 英文）+ 架构图
  （docs/architecture.svg，README 内嵌 mermaid）+ 与 Wazuh 对比表
- [ ] 演示视频/GIF（可选增量，不影响可发布状态）

## 5. 验收标准

- 导入样本日志后，看板正确显示暴力破解告警（含源 IP、次数、时间窗）
- 修改被监控目录下文件，1 分钟内产生 FIM 告警
- 新增一条 YAML 规则**不改代码**即可生效

## 6. 附录：面试问答要点

- Q: 和 Wazuh/osquery 比你的价值？ → A: 学习其架构思想并最小化实现，
  能说清 SIEM 的数据链路：采集→解析→规则匹配→抑制聚合→展示。
- Q: 为什么用滑动窗口而不是总量统计？ → A: 暴力破解是时间密集行为，
  总量统计会被长期低频尝试绕过；窗口大小与阈值的权衡是规则调优的核心。
- Q: 告警风暴怎么处理？ → A: 两层：引擎内按 (规则, 分组键) 静默
  （同规则不重复报）+ 抑制器按 (源 IP, 时间窗) 聚合成 Incident
  （不同规则的关联告警合并呈现，且保留成员列表可解释）。
- Q: FIM 用 mtime 还是哈希？ → A: **哈希**。mtime 可以被 `touch` 伪造，
  SHA256 不行——完整性检查的本质是"内容没变"，不是"时间戳没变"。
  代价是 IO/CPU 成本，所以要有排除规则（.git/__pycache__）和流式读取。
- Q: 告警聚合为什么按源 IP 而不是按规则？ → A: 分析师响应单位是"一次攻击"，
  不是"一条规则"。同一 IP 的暴力破解 + 用户名枚举 + 后续 FIM 篡改
  很可能是一条攻击链，聚合成一个 Incident 才能看出全貌；
  但**聚合不能丢成员**——每个 Incident 保留完整告警列表，否则就是藏问题。
- Q: 看板为什么不用 FastAPI + Chart.js？ → A: 三个理由：① 安全工具常在内网/
  隔离环境演示，CDN 抽风整个看板白屏；② 安全工具自身加载第三方 JS 是供应链
  攻击面；③ 零依赖"拷走即跑"的部署体验。**在安全场景里，依赖决策本身就是
  技术判断**——这不是"不会用框架"，而是场景驱动的取舍（可引申讲依赖审计/SBOM）。
- Q: 为什么事件和告警分表存储？ → A: 可解释、可取证。每条告警必须能回溯到
  原始事件（"这条 HIGH 是基于哪 5 条 failed_password 得出的"），这是审计类
  系统的基本要求，也是与玩具项目的分水岭。
- Q: 看板和报告为什么要做两个出口？ → A: 消费场景不同：看板面向"正在值班的
  人"（实时、可交互、按时间倒序）；报告面向"事后复盘与交付"（静态、可打印、
  按严重度排序）。同一份 DB、同一套聚合——report.py 直接复用 web/server.py 的
  build_api_payload，单一定义源，两套出口不会各漂各的。这是 SIEM 产品里
  Dashboard 与 Report 的标准分工。
- Q: 报告为什么导出 HTML 而不是直接生成 PDF？ → A: 三个原因：① Python PDF 库
  （reportlab/wkhtmltopdf）引入重量级依赖，中文字体嵌入是出了名的坑；
  ② HTML + @media print 让浏览器负责分页/字体/打印色彩，Ctrl+P 即得 PDF；
  ③ HTML 本身就是最好的交付格式——可邮件附件、可挂内网、可 diff。
  在安全场景里，"少一个依赖"永远是对的。
- Q: 报告里为什么附"检测规则清单"？ → A: 可解释性。报告的每条结论都必须能
  回答"这条告警是哪个规则、什么窗口/阈值得出的"——否则分析师无法判断该不该
  升级处置。这也是审计合规的基本要求（检测逻辑要可审计）。
- Q: 报告生成器自己怎么防 XSS？ → A: 被分析的日志内容本身就是攻击载荷
  （攻击者会往 User-Agent 里写 `<script>`）。所有入库字段进 HTML 前一律
  html.escape——安全工具的自我要求：**分析危险数据的工具，自己不能成为注入
  载体**。这条有专门的测试用例守着。
- Q: 阈值检测和签名检测怎么分工？ → A: 阈值检测抓"行为模式"（爆破、枚举——
  慢，但不需要知道攻击长什么样）；签名检测抓"已知攻击特征"（Log4Shell 的
  ${jndi: 载荷——快，但只覆盖已知）。真实 IDS 两者都有（Suricata 的
  threshold + rule 就是这个分工）。我的规则引擎把两种判据做成同一个 YAML
  里的可选字段，新增签名规则不改代码。
- Q: 签名匹配为什么是 AND/OR 两个显式算子？ → A: 安全规则最怕"我以为它在
  匹配这个"。raw_contains 列表是 AND（收窄），raw_contains_any 是 OR
  （同族变体），语义写死在引擎里，不靠约定俗成——规则的正确性必须可预测。
- Q: 采集器为什么要"领域解析 + 保底解析"两层？ → A: 领域解析器（auth_log）
  给结构化字段（user/ip/port），但只认识自己那几种消息；保底解析器
  （app_log）不丢任何行——真实 SIEM 的采集层就是这个分层，覆盖率优先。
  Log4Shell 的痕迹在应用日志里，没有保底解析器就永远检测不到。
- Q: 签名规则 threshold=1，静默期内的同类匹配去哪了？ → A: 告警侧折叠
  （防告警风暴），事件侧全留存（events 表可下钻）。Wazuh 的 frequency
  字段会把被抑制次数合并进告警，我选择"告警不合并、事件全留存"——
  已知取舍，说得出代价：分析师要看"到底打了几次"必须下钻事件表。
