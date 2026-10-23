---
title: "我用 Python 给自己写了个迷你 osquery：主机入侵检测实践"
tags: 安全运维,入侵检测,Python,SIEM,日志分析
categories: 安全
---

# 我用 Python 给自己写了个迷你 osquery：主机入侵检测实践

> osquery 很强，但要装 Agent、起 RocksDB、学 SQL 查 osquery 表。
> 我想要的是一个**单机能跑、零外部服务、打开就能用**的主机检测工具——
> 于是自己写了一个：**SentinelWatch**。
>
> 它做四件事：日志采集与检测、文件完整性监控（FIM）、告警聚合与抑制、
> 报告与看板导出。50 个单元测试，检测规则来自我自己复现 CVE 时产生的真实日志。
>
> 这篇文章讲三个我认为最有价值的设计决策，以及它们各自的取舍。

---

## 一、定位决定架构：我要解决什么问题

先想清楚边界，再写代码：

| 问题 | 我的选择 |
|---|---|
| 部署环境 | 单台主机 / 内网机器，可能没有外网、没有 Docker、没有 root |
| 数据量 | 单机日志量级（auth.log、应用日志），不是集群级 |
| 使用方式 | 安全工程师或运维打开就用，能现场演示 |
| 依赖约束 | **零外部服务**是硬约束——不能要求用户先装 ES |

基于这个定位，技术选型几乎没有悬念：
**Python 标准库为主**（运行时只依赖 PyYAML 读规则）、**SQLite 存储**、
**看板用 `http.server` + 服务端渲染内联 SVG**（不引前端框架）。

> 有人会问：为什么不用 Elasticsearch？
> 因为这个工具的价值在"零部署成本"，不在"海量查询能力"。
> 真要上量，存储层接口已经分好了，换 ES 是演进路径，不是重写——
> 但**为了想象中的规模牺牲当下的可用性，是过度设计**。

---

## 二、设计决策一：双采集器（领域解析 + 通用保底）

这是我从真实 SIEM 的采集层学来的分工。

```python
collectors/
├── auth_log.py    # 领域解析器：懂 auth.log 的格式
└── app_log.py     # 保底解析器：任何非空行都成为事件
```

**领域解析器**负责"字段质量"：从 auth.log 里抽出时间、事件类型
（`invalid_user` / `Accepted password` / `Failed password`）、
用户名、来源 IP、端口。检测规则依赖这些结构化字段。

**保底解析器**负责"不丢行"：任何看不懂的行也变成一条事件
（`event_type = "app_log"`，原始行完整保留）。

```python
def parse_line(line: str) -> AuthEvent | None:
    if not line.strip():
        return None          # 空行除外
    ...
```

**为什么"不丢行"这么重要？**
因为漏洞利用产生的痕迹经常出现在你**没有预置解析器的日志**里。
比如 Log4Shell 的 payload 在应用日志、Fastjson 的 `@type` 在请求日志——
如果你只解析 auth.log，这些痕迹你根本看不到。

> 这也直接支撑了后面的 CVE 检测：**Fastjson 的检测规则跑在 app_log 采集器上**，
> 而我当初就是靠"保底解析器不丢行"才把攻击日志完整留下来的。

---

## 三、设计决策二：阈值 + 签名双模规则引擎

只做阈值检测（"5 分钟内 5 次失败登录"）会漏掉**一次就够**的攻击；
只做签名检测（"出现 `${jndi:`"）会漏掉**缓慢爆破**。
所以规则引擎做成双模：

```yaml
# 阈值型：多少次算异常
- id: ssh-bruteforce
  severity: high
  event_types: [auth_log]
  group_by: [ip]
  window_seconds: 300
  threshold: 5            # ← 阈值模式

# 签名型：出现什么特征就是它（v1.0 新增的可选 match 条件）
- id: log4shell-jndi-payload
  severity: critical
  event_types: [app_log]
  threshold: 1
  match:
    raw_contains: ["${jndi:"]      # ← 签名模式，AND 语义
```

签名匹配用了两个**显式算子**，不靠约定俗成：

- `raw_contains`：列表里所有子串都要出现（**AND**，收窄匹配）
- `raw_contains_any`：任一子串出现即匹配（**OR**，同族变体）

比如 Fastjson 的 expectClass 绕过规则，就要用 AND：
```yaml
match:
  raw_contains:
    - "@type"                    # 单独出现不告警（正常 JSON 也可能有）
    - "java.lang.AutoCloseable"  # 两个特征同时出现才报
```
**安全规则的匹配条件必须可预测**——AND/OR 写清楚，比"看规则名字猜"可靠得多。

### 检测的底层：滑动窗口

阈值判定用 `deque` 双指针实现的滑动窗口：
右侧指针吞入新事件，左侧指针弹出超窗事件，窗口内计数即命中数。
O(n) 完成全部判定，不需要对每个事件回扫全表。

---

## 四、设计决策三：告警聚合与静默（以及一个我坚持的取舍）

一条 SSH 爆破在日志里是 500 行，如果每行都告警，看板会被刷爆。

**聚合**：同源事件（同规则 + 同来源 IP）合并为一条 Incident，
告警里带 `event_count`、时间窗口、涉及用户列表。

**静默期**：同源告警在 `suppress_seconds` 内不重复报（规则级可配）。

**但我坚持的一个取舍**：**事件全留存，不合并原始数据**。
聚合只发生在"告警层"，数据库里每条事件都独立可查——
因为运营排查时需要下钻到原始日志行，
不能只看到一个合并后的计数就把线索断了。

> 这个取舍是有代价的：存储增长更快。
> 但我把"可下钻"看得比"省存储"重——**告警是给人看的，排查是给数据用的，
> 两层不能混。** 我在测试里把这个语义固定住了（静默期内的每条事件都要能查到）。

---

## 五、文件完整性监控（FIM）

```bash
python cli.py fim --dir ./rules --baseline fim_baseline.json
```

对监控目录计算每个文件的 SHA256 存为基线；再次运行时对比，
输出**新增 / 修改 / 删除**三类变更。对 Web 目录、规则目录、二进制目录做基线监控，
能发现"被改了但没人承认"的文件。

工程细节：哈希**流式计算**（不整文件读入内存），
且基线文件如果放在被监控目录内会把自己算成新增文件——
所以 CLI 会显式检查并报错提示（这个坑我踩过，写进了工具里）。

---

## 六、最有成就感的部分：检测规则来自我自己的漏洞复现

这是我这个项目和"教程项目"最大的区别。

我在复现 Log4Shell（CVE-2021-44228）和 Fastjson（CNVD-2022-40233）时，
**受害应用的真实日志**直接变成了 SentinelWatch 的检测样本：

| 来源 | 痕迹 | 规则 |
|---|---|---|
| Log4Shell 实验 B（RCE 成功） | `${jndi:ldap://...}` 明文残留 | critical |
| Log4Shell 实验 A（代码基被拒） | `com.sun.jndi.ldap.LdapCtx@xxxx` | high |
| Log4Shell 实验 C（反序列化） | `com.sun.rowset.JdbcRowSetImpl@xxxx` | high |
| Fastjson 实验 A（JNDI 被拒） | `set property error, autoCommit` | high |
| Fastjson 实验 C（缓存绕过） | `"@type":"java.lang.Class"` | critical |
| Java 17 模块封装打断攻击 | `InaccessibleObjectException` | medium |

**这里有一个我认为最重要的认知**：

> **检测不依赖"利用成功"。**
> Log4Shell 被 JVM 的 `trustURLCodebase=false` 挡下、攻击失败了，
> 但日志里照样留下 payload 明文和 `LdapCtx@` 残留；
> Fastjson 被挡下也留下 `set property error, autoCommit`。
>
> **把"攻击失败"也当成告警信号，是防守方与攻击方视角的根本差异。**
> 攻击者只需要成功一次；防守方要把每一次尝试都变成可见的。

端到端实测：9 条日志（6 攻击 + 3 正常业务）→ 6 条告警命中各自规则，
**正常业务行零误报**。

---

## 七、面试要点

1. **Q：为什么不用 osquery / Beats？**
   A：定位不同。我要的是零部署、单机可用、能现场演示的工具；
   osquery 的能力更强但引入 Agent + 存储的运维成本。
   选型看约束，不看"哪个更有名"。
2. **Q：阈值检测和签名检测怎么配合？**
   A：阈值管"多少次"（慢速爆破），签名管"是什么"（一次性的特征攻击）。
   双模引擎 + AND/OR 显式算子，两者可预测。
3. **Q：告警合并了，原始数据呢？**
   A：聚合只发生在告警层，事件全留存可下钻。
   告警是给人看的，排查是给数据用的，两层不混。
4. **Q：你的检测规则从哪来？**
   A：从我自己复现 CVE 的真实日志反推，不是抄公开规则。
   这也让我能讲清楚每条规则对应哪个攻击场景、以及它为什么可靠。

---

## 合规声明

所有检测规则样本均来自本地授权环境的复现实验，不含任何真实攻击流量。

---

> 完整代码：`sentinelwatch/`（引擎、双采集器、FIM、抑制器、看板、报告导出）。
> 50 个单元测试，其中 23 个专门覆盖检测规则（Log4Shell 11 + Fastjson 12）。
> 检测规则文件：`rules/log4shell.yaml`、`rules/fastjson.yaml`。
