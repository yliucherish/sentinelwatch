# 数据集获取与选型

> 本文件只讲"数据从哪来、为什么选它、下载后怎么处理"。
> 评测脚本用法见 [`run_benchmark.py`](run_benchmark.py)，结果报告见 [`BENCHMARK.md`](BENCHMARK.md)。

## 为什么必须用外部数据集

自造的 8 包演示样本能证明"代码跑得通"，证明不了"检测器好不好"——自己出题
自己答，永远满分。要拿外面的尺子量，才有说服力：

| 指标 | 含义 | 自造样本能不能给 |
|---|---|---|
| 检出率 | 第三方标注为攻击的请求抓到多少 | ❌ 样本是我按规则造的，必然 100% |
| 误报率 | 第三方标注为正常的请求误报多少 | ❌ 我没有真实业务流量 |
| 吞吐 | 单线程 MB/s、请求/s | ⭕ 能测，但样本太小没有代表性 |

## 先说一个必须先解决的问题：攻击类型不重叠

**CIC-IDS2017 是 2017 年的数据集，它的 Web 攻击类型是：**

| 攻击类型 | 样本数 | 我的规则能检出吗 |
|---|---|---|
| Web Attack – Brute Force | 1507 | ❌ 表单爆破没有特征载荷，靠频次判据 |
| Web Attack – XSS | 652 | ❌ 当前没有 XSS 规则 |
| Web Attack – SQL Injection | 21 | ❌ 当前没有 SQLi 规则 |

**而 SentinelWatch 现有 13 条签名规则全是 Log4Shell（2021）/ Fastjson / WebShell。**
2017 年的数据集里不可能有 2021 年的漏洞利用。

所以直接拿现有规则跑 CIC 周四，**检出率会是 0%**——这个数字既不丢人也不光荣，
它只是"我在测一个我的规则根本没打算覆盖的东西"。

有两条路，必须选一条：

### 路线 A：先扩规则，再测 CIC（✅ 已于 v1.5 执行）

给 SentinelWatch 补 3–4 条 Web 攻击规则（SQLi / XSS / 目录遍历 / 扫描器指纹）。
这本来就是"入侵检测平台"该有的能力，现在只有 Log4Shell + Fastjson 太窄。

**实际补了 7 条**（`rules/http_web_attacks.yaml`）：SQLi 四类、XSS 两类、路径遍历。
补完之后：
- **CIC 周四** → 检出率（SQLi 21 条 + XSS 652 条有明确载荷特征，签名可检测）
- **CIC 周一**（529918 条纯良性）→ 误报率
- **Brute Force 1507 条** → 检不出（没有载荷签名、需要响应码或频次），
  **这本身就是一个诚实且值钱的发现**——正好对应方案要求的"至少记录 2 个暴露的局限"

### 路线 B：换成含 Log4Shell 的流量

找 2021 年 12 月之后的抓包（malware-traffic-analysis.net 有 Log4Shell 相关样本），
小体积、可直接下载。代价是：样本量小、误报率测不准（良性流量不够）。

**我的建议是 A**，因为扩规则是"补短板"，而换数据集是"回避短板"。

## CIC-IDS2017 获取方式（现状：需注册表单，注册后才给文件列表）

### 官方页面

https://www.unb.ca/cic/datasets/ids-2017.html

### ⚠️ 下载入口到底在哪（2026-11 逐页实测，别再找错地方）

这个站点的信息架构很容易让人卡住：`Available datasets` 列表页上**没有任何下载按钮**，
详情页正文里也**没有**。真正的入口藏在详情页**最底部**。

```
Available datasets 页
  └─ IDS datasets 分组（第 5 项）
       └─ Intrusion Detection Evaluation Dataset (CIC-IDS 2017)   ← 点这个蓝色链接
            └─ 详情页 → 滚到最底部 → License 段落最后一行
                 └─ "Download this dataset"                        ← 点这个
                      └─ https://cicresearch.ca/CICDataset/CIC-IDS-2017/
                           └─ 黑底橙字的 "CIC DATASET DOWNLOAD FORM"
                                └─ 填 5 项必填 + 国家 → Submit
                                     └─ 弹窗 "Ready" → 按钮变 "Browse files"
                                          └─ 点它，新标签页 = 文件列表
```

表单必填字段（`CIC DATASET DOWNLOAD FORM`）：

| 字段 | 说明 |
|---|---|
| First Name / Last Name | 真实姓名即可 |
| Email | 会收一封确认信 |
| Organization/Company | 学校名，如 `XXXX University` |
| Job Title | `Undergraduate Student` / `Researcher` |
| Country | 下拉选 `China` |

### 注册门禁的技术细节

提交走 `POST → insert.php`，返回 JSON `{ok:true, redirect:"browse.php"}`，
前端拿到 `redirect` 才允许打开文件列表页。**没有注册直接访问会被拦**：

```bash
$ curl -sS -o /dev/null -w "%{http_code}\n" https://cicresearch.ca/CICDataset/CIC-IDS-2017/browse.php
403
$ curl -sS https://cicresearch.ca/CICDataset/CIC-IDS-2017/browse.php
Registration required. Please go back and register.
```

所以如果要用 `curl` / `wget` 批量拉，正确姿势是：先用 `curl -c cookies.txt` 提交表单，
再带 `-b cookies.txt` 请求 `browse.php`，从 HTML 里解析出真实文件地址（这些地址**不在
`browse.php` 之前可见**，无法预先拼出来）。

**结论：本仓库不提供自动下载脚本**——数据获取这一步必然要人工过一次注册表单。

### 顺带复核：老直链确实已死（2026-11 实测）

猜路径拼直链是行不通的，两道跳转都会把你弹回官网：

```bash
$ curl -sI http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/Thursday-WorkingHours.pcap
HTTP/1.1 301 Moved Permanently
Location: https://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/Thursday-WorkingHours.pcap

$ curl -sI https://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/Thursday-WorkingHours.pcap
HTTP/1.1 302 Found
Location: https://www.unb.ca/cic/datasets/index.html
```

即 `301 → 302 → 官网首页`，拿不到字节。真实文件路径只在 `browse.php` 的 HTML 里，
而 `browse.php` 需要先注册。

### 需要的文件

官方页面给的体积：

| 文件 | 大小 | 用途 | 现在下不下 |
|---|---|---|---|
| `PCAPs/Thursday-WorkingHours.pcap` | 7.8 GB | 检出率 **和** 误报率 | ⬜ 还没下（**下一步就是它**） |
| `PCAPs/Tuesday-WorkingHours.pcap` | 11.0 GB | 纯良性的 HTTP 语料 → 只出误报率 | ✅ 已下（11,048,283,608 字节） |
| `PCAPs/Monday-WorkingHours.pcap` | 11 GB | 独立的纯良性日 | ❌ 不必了，周二已覆盖 |
| `CSVs/MachineLearningCSV.zip` | 几百 MB | 用不上 | ❌ 不需要 |

**先跑周二、再跑周四**，两个文件各管一个数：

| 问题 | 谁来回答 | 为什么 |
|---|---|---|
| 误报率（在真实业务流量里会不会乱报） | **周二** | 这一天的攻击只有 FTP / SSH 爆破，**没有一条 HTTP 攻击**，所以按 HTTP 请求的事件粒度看它是纯良性语料；11 GB 全是负样本，分母极大 |
| 检出率（真攻击能不能抓到） | **周四** | 只有周四有 Web 攻击（Brute Force / XSS / SQLi），而现有签名规则正是打这些的 |

两个都要，但顺序无关。周二先跑是因为它已经在本地了。

#### 周二为什么"也是良性"，而不是"没有攻击"

周二的标注里确实有 FTP-Patator（约 09:20–10:20）和 SSH-Patator（约 14:00–15:00），
但这两场攻击打的是 21/22 端口，**不产生任何 HTTP 请求**。本工具的流量采集器只还原
HTTP（见 `collectors/pcap.py` 的已知限制），所以这一天在"按 HTTP 请求"这个粒度下
天然全是负样本。

这件事必须写在报告里，而不是含糊过去：**漏报 FTP 爆破不是检测器的 bug，是数据源
覆盖范围的问题**——同一场爆破在 `auth.log` 里是可见的（项目有 SSH 爆破规则），
换一个采集器就抓得到。这也正好是"日志 + 流量双数据源"这个设计要说明的事。

#### 官方发的是 pcapng，不是 pcap

`Tuesday-WorkingHours.pcap` 这个名字骗人：文件头 4 字节是 `0a 0d 0d 0a`
（pcapng 的 Section Header Block），**不是**经典 libpcap 的 `d4 c3 b2 a1`。

v1.5 起 `collectors/pcap.py` 原生支持 pcapng，不需要 `tcpdump` / `editcap` 转格式。
如果拿到的是更老的 pcap 也能读，两种容器走同一个出口，上层无感。

校验方法（不装任何工具）：

```bash
head -c 4 data/Tuesday-WorkingHours.pcap | xxd        # 0a0d0d0a = pcapng；d4c3b2a1 = pcap
```

#### 为什么周一那 11 GB 先不下

周四一个文件就能出完整的四格矩阵。评测口径是「落在攻击时间窗内 **且** 源 IP 为
攻击源」，而周四 09:20–15:45 里只有约两小时是攻击窗（见下方时间表），
**其余四个多小时全是负样本**。所以：

- 检出率 ← 攻击窗内的请求
- 误报率 ← 攻击窗外的请求（同一天、同一批用户、同一条链路）

这不是凑数：负样本来自真实业务流量，不是合成的。周一的增量价值是
"再加一个完全独立的良性日"——结论方向不会变，只是措辞能更强一点。

**先跑周四。** 如果周四 FP=0 而你想要一个更强的独立佐证，再做二选一：

1. 下周一 11 GB（约 13 分钟解析），得到"在一个零攻击的完整工作日里 0 误报"；
2. **自抓 200 MB 浏览流量**（零下载，几分钟就够）——更划算，而且 2026 年的真实
   流量里 TLS 占比、UA 分布都跟 2017 年不同，作为"当代良性样本"比 2017 年的
   周一更有说服力。

#### 那个 CSV 用不上（更正一处早先的说法）

我此前说"下 50 MB 的 CSV 来校时区"。**这个建议是多余的**，而且容易误导：
`MachineLearningCSV.zip` 是整包，解压后才是单日文件，而且里面是 CICFlowMeter 抽的
80 多个**流特征**（包长统计、字节数、标志位），**不含任何 payload**——喂给签名规则
一条也匹配不出来。

校时区根本不需要它。官网写明"数据采集始于 2017 年 7 月 3 日上午 9 点（EDT）"，
所以拿到周四 pcap 后：

```bash
tcpdump -r Thursday-WorkingHours.pcap -c 1 -n -tttt
```

看第一个包显示几点，与"7 月 6 日上午 9 点前后"一减，就是
`pcap_time_offset_hours`。**一个包就够。**

### 下载后处理

```bash
# 1) 确认容器格式（本解析器两种都吃，这一步只是留个记录）
head -c 4 Thursday-WorkingHours.pcap | xxd      # 0a0d0d0a = pcapng；d4c3b2a1 = pcap

# 2) 不必切片，直接跑。要切片先看「不要切片」那一节
python bench/run_benchmark.py data/Thursday-WorkingHours.pcap \
       --labels bench/labels/cic_ids2017_thursday_web.json
```

**不要切片。** 早期版本的做法是 `editcap -c 200000` 切出 200k 包先跑通，但
pcapng 按块切、切片工具未必保留 Interface Description Block（丢了就解析不出
链路类型和时戳精度），而且**切出来的 200k 包大概率不含攻击窗**——落在里面的
只会是零星的正常流量，跑出来的"检出率 0%"是切片的锅，不是检测器的锅。
v1.5 起解析器吞吐约 97 MB/s，11 GB 全量一百多秒就跑完，切片的收益已经为负。

切片的唯一合理用途是**调试解析错误**，且要用按时间而不是按包数的切法。

## 标注文件：`labels/cic_ids2017_thursday_web.json`

标注不用数据集自带的 flow 标签，而用「时间窗 + 攻击源 IP」——原因见
`run_benchmark.py` 顶部的说明（标签按 flow、事件按 request，粒度不同）。

时间窗来源（公开可引用）：

> Sharafaldin et al., *Toward Generating a New Intrusion Detection Dataset and
> Intrusion Traffic Characterization*, ICISSP 2018；
> 以及 MDPI *Early-Stage Detection of Cyber Attacks* (2020) Table 4 给出的
> 周四攻击时段与攻击者 IP。

| 攻击 | 时间（当地） | 攻击者 | 受害者 |
|---|---|---|---|
| Web Attack – Brute Force | 09:20 – 10:00 | 205.174.165.73 | 205.174.165.68 |
| Web Attack – XSS | 10:15 – 10:35 | 205.174.165.73 | 205.174.165.68 |
| Web Attack – SQL Injection | 10:40 – 10:42 | 205.174.165.73 | 205.174.165.68 |

### ⚠️ 坑一：攻击者 IP 在 pcap 里根本不存在

上表里的 `205.174.165.73` **在抓包里一条也找不到**。CIC-IDS2017 的抓包点在防火墙
内侧，外网攻击者进来时源 IP 已被 NAT 改写成网关 `172.16.0.1`。

实证（周二全量，11,551,954 包）：

| 观察 | 数字 |
|---|---|
| 端口 21 的 SYN 源 IP | `172.16.0.1` 3,978 个，其余源 IP 全为内网 `192.168.10.x` |
| 48,345 条 HTTP 请求的源 IP | **全部** `192.168.10.x`，`172.16.0.1` 一条都没有 |

内网客户端直连外网不经 NAT（所以 HTTP 请求源 IP 是内网的），而外网打进来的
连接一律显示为网关地址。因此 `src_ip == 172.16.0.1` 是一个干净的「从外网进来」
标记——标注文件 `attack_windows[].src_ips` 填的必须是这个地址，不是公网 IP。

### ⚠️ 坑二：时区偏差是 3 小时，不是 4 小时

标注文件里的 `pcap_time_offset_hours`：

```
标注时间 + offset = PCAP 里的时间戳
```

**UNB 在弗雷德里克顿（新不伦瑞克），属大西洋时区，夏令时是 ADT = UTC−3，
不是东部时区 EDT = UTC−4。** 按 4 填会整体晚一小时——而 SQLi 窗只有两分钟宽，
一小时误差足以把这批样本整段挪进空地，检出率归零，且看起来像"检测器坏了"。

三条独立证据（都在周二那份 11 GB 上实测）：

| 证据 | 论文/文档 | PCAP 实测（UTC 基准） | 结论 |
|---|---|---|---|
| FTP-Patator 止点 | 10:20 | 13:20 | +3h，完全吻合 |
| FTP-Patator 起点 | 09:20 | 12:05 | +2h45m，早 15 分钟（论文四舍五入到整十分） |
| SSH-Patator 起点 | 14:00 | 16:50 | +2h50m |
| 整天抓包跨度 | 办公时段 9:00–17:00 | 11:53–20:00 = 08:53–17:00 ADT | +3h，两端都吻合 |

复核命令（本仓库自带，不需要 tcpdump）：

```bash
python tools/probe_window.py data/Tuesday-WorkingHours.pcap 21 22
```

它会按分钟统计目标端口的 SYN 数，直接打印突增段的 UTC 与 EDT 两种墙钟时间。
把某段与论文时间窗对齐，差值就是 offset。


## 备选数据集

| 数据集 | 获取 | 适合 | 不适合 |
|---|---|---|---|
| **malware-traffic-analysis.net** | 直接下载，单个 zip 几十 MB | 真实企业流量、含 C2/下载器 | 主要不是 Web 应用攻击，与现有规则重叠少 |
| 自己抓自己的浏览流量 | 浏览器 + tcpdump/Wireshark | **误报率**的良性样本补充 | 无标注，只能做误报测量 |

自己抓一段正常浏览流量（1000+ 请求）当良性样本，是个成本极低、效果很好的补充
——真实用户流量里什么畸形请求都有，比合成样本更能暴露误报。

## 数据不进仓库

PCAP 体积远超 git 的合理范围。`.gitignore` 已忽略 `data/` 与 `out/`。
本仓库只提交：标注文件、评测脚本、评测报告（`.md`）与逐事件明细的**抽样**。

## 许可与合规

- CIC-IDS2017：CIC 明确用于研究目的，引用时需注明来源（见 `BENCHMARK.md`）。
- malware-traffic-analysis.net：公开样本，使用时遵循站点说明。
- 自己抓的流量：只抓自己的，不抓他人——这是底线，不是建议。
