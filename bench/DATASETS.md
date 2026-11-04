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

## CIC-IDS2017 获取方式（现状：需表单，直链已失效）

### 官方页面

https://www.unb.ca/cic/datasets/ids-2017.html

### 直链情况（2026-11 实测）

老地址 `http://205.174.165.80/CICDataset/...` 仍会响应，但返回 **301/302 重定向
回官网页面**，不再提供文件直下：

```bash
$ curl -sIL "https://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/Thursday-WorkingHours.pcap"
HTTP/1.1 302 Found
Location: https://www.unb.ca/cic/datasets/index.html
```

**结论：现在必须通过官网表单申请 / 用浏览器下载，`wget` 直链不行。**
所以本仓库不提供自动下载脚本——数据获取这一步需要人工完成。

### 需要的文件

| 文件 | 大小 | 用途 |
|---|---|---|
| `Thursday-WorkingHours.pcap` | 7.7 GB | 检出率（含 Web Attack） |
| `Monday-WorkingHours.pcap` | 10 GB | 误报率（纯良性） |

**别一上来下 17.7 GB。** 先下周四，切成 200 MB 的小段跑通流程，再决定要不要跑全量。

### 下载后处理

```bash
# 1) 确认是经典 pcap 而不是 pcapng（本解析器不支持 pcapng）
file Thursday-WorkingHours.pcap
# 若是 pcapng：
tcpdump -r Thursday-WorkingHours.pcapng -w Thursday-WorkingHours.pcap

# 2) 切一段先跑通（按包数切，比按时间稳）
editcap -c 200000 Thursday-WorkingHours.pcap thu_200k.pcap

# 3) 核对时间戳与链路类型
tcpdump -r thu_200k.pcap -c 3 -n
```

第 3 步很重要：**PCAP 里的时间戳时区，与论文里写的时间窗，通常不一致。**
见下面的标注文件。

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

### ⚠️ 时区对齐（不做这步会得到"检出率 0%"）

标注文件里的 `pcap_time_offset_hours` 就是干这个的：

```
标注时间 + offset = PCAP 里的时间戳
```

**怎么定这个值**：取 PCAP 前几个包的时间戳，与上面表格对比。
若 PCAP 显示 13:20 而文档说 09:20，则 offset = +4（PCAP 是 UTC，文档是 EDT）。

核对命令：

```bash
tcpdump -r thu_200k.pcap -c 1 -n -tttt
```

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
