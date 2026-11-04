# 基准评测报告

> **状态：方法学就绪，真实数据集结果待填。**
> 缺的不是代码，是数据——CIC-IDS2017 现在必须走官网表单申请，
> 无法脚本直下（实测见 [`DATASETS.md`](DATASETS.md)）。
> 在数字填进来之前，本文件不会写任何"看起来像结果"的东西。

## 1. 评测口径（先定口径，再看数字）

数据集标签按 **flow** 打，本工具产出按 **HTTP 请求** 的事件。粒度不同，硬对齐
会算错。所以评测不使用数据集自带标签，而用显式声明的口径：

```
落在某攻击时间窗内 且 源 IP 为该窗的攻击源 IP  → 应检出（positive）
其余请求                                        → 应放行（negative）
```

两个条件缺一不可。只按 IP 判会把攻击者在非攻击时段的正常流量算成攻击，人为
抬高检出率；只按时间窗判会把同网段正常用户算成攻击，人为抬高误报率。

**只有签名规则进混淆矩阵。** 阈值规则（窗口聚合）是另一个粒度：一次爆破的
5 条失败请求，无法逐条标注"哪条该告警"。混进来算，指标就没有意义了。

## 2. 结果

### 2.1 脚本自检（合成样本，已验证 ✅）

这不是数据集结果，是"评测脚本本身对不对"的证明——如果连脚本都有 bug，
跑出来的数就没意义。用 `tools/pcapgen.py` 的演示样本，标注为
「2 条正常 + 3 条攻击」：

```bash
$ python bench/run_benchmark.py --self-test
自检结果
  事件 5 条：TP=3 FN=0 FP=0 TN=2
  检出率 100%，误报率 0%
[+] 自检通过：脚本的判定与计数逻辑正确，可以拿去跑真实数据集
```

| 项 | 值 |
|---|---|
| 事件数 | 5 |
| 混淆矩阵 | TP 3 / FN 0 / FP 0 / TN 2 |
| 判定 | 与标注完全一致 |

### 2.2 真实数据集（待填 ⬜）

| 数据集 | 用途 | 检出率 | 误报率 | 吞吐 | 状态 |
|---|---|---|---|---|---|
| CIC-IDS2017 周四 Web 攻击 | 检出率 | — | — | — | ⬜ 待下载 |
| CIC-IDS2017 周一 | 误报率 | — | — | — | ⬜ 待下载 |
| 自抓浏览流量（1000+ 请求） | 误报率补充 | — | — | — | ⬜ 待采集 |

**为什么空着**：CIC 的 PCAP 单文件 7.7–10 GB，官网直链已失效（302 回表单页），
需要人工下载。填假数字比空着更糟——这个项目的全部价值就在"数字是真的"。

## 3. 已暴露的问题（这部分是真的）

跑基准的第一件事不是拿到数字，是发现"自造样本永远发现不了的问题"。
目前已经暴露 1 个，并且修了：

### 3.1 解析器把整个文件读进内存 → 7.7 GB 直接 OOM（已修）

`_iter_records()` 原来用 `Path(path).read_bytes()` 一次性读入全文件。
自造的 8 包样本 1.5 KB，永远测不出这个问题；CIC 单日 7.7 GB，
进程第一秒就被打死。

修法（v1.4）：

- `_iter_records()` 改为逐条记录从文件读——PCAP 记录头自带长度，天然可分帧，
  流式读不需要任何妥协；
- 新增 `iter_events()` 流式接口：一条流空闲超过 300 秒就当场拼装产出并释放，
  **内存上界由"活跃流数量"决定，不再由文件大小决定**；
- 加 `_MAX_FRAME = 256 KB` 上限：文件损坏导致 `incl_len` 是垃圾值时直接报错，
  而不是尝试 `f.read(4GB)`；
- `parse_file()` 保留（中小文件、需要全局时间序），内部行为不变。

覆盖这三点的测试：`tests/test_pcap.py` 里的
`test_iter_events_matches_parse_file`、`test_iter_events_keeps_all_requests_in_keepalive_flow`、
`test_iter_events_releases_idle_flows`、`test_iter_records_rejects_absurd_frame_length`。

**这个 bug 值钱的地方**：它只有在"文件比内存大"时才出现。说明**换一把尺子
才能看见自己的剑有多长**——这正是做公开数据集评测的意义，与检出率高低无关。

### 3.2 预计还会暴露的（等真实数据验证）

按已知边界推测，跑 CIC 时大概率会撞上这些（`README` 的"已知限制"里已列，
此处是"等实测确认"清单）：

| 预期问题 | 为什么会撞上 | 是 bug 还是边界 |
|---|---|---|
| chunked / gzip body 解析不到 | 只按 `Content-Length` 取体 | 边界（已在 README 声明） |
| 非 80 端口的 HTTP 被当流量丢弃 | 解析器不按端口过滤，但 CIC 有 8080 服务 | 待确认 |
| 大量 TCP 握手/挥手空包 | 数据集混杂全部流量 | 应静默跳过（已实现，需确认不崩） |
| 攻击类型不重叠导致检出率极低 | CIC 是 2017 年数据，没有 Log4Shell | **不是 bug，是选题问题**，见下 |

### 3.3 一个前置的选题问题（已处理）

CIC-IDS2017 的 Web 攻击是 **SQLi（21）/ XSS（652）/ Brute Force（1507）**，
而当时 13 条签名规则全是 **Log4Shell（2021）/ Fastjson / WebShell**。
直接跑，检出率会接近 0——但这个 0 说明的是"我在测一个规则没打算覆盖的东西"，
不是"检测器不行"。

**已按 `DATASETS.md` 的路线 A 处理**：v1.5 补了 7 条 Web 攻击规则
（SQLi 四类 / XSS 两类 / 路径遍历，见 `rules/http_web_attacks.yaml`）。
补完之后各段的预期：

| CIC 周四攻击 | 样本数 | 现在能测吗 | 说明 |
|---|---|---|---|
| Web Attack – SQL Injection | 21 | ✅ | UNION / 布尔盲注 / 时间盲注 / 元数据探测 四类判据都有 |
| Web Attack – XSS | 652 | ✅ | `<script` 与事件处理器注入覆盖主流 payload |
| Web Attack – Brute Force | 1507 | ❌ **检不出** | 表单爆破没有特征载荷，需要"响应码 + 频次"判据；而当前解析器只取客户端方向、不提取响应状态码 |

**那 1507 条"检不出"不要藏。** 它正好是方案要求的"至少 2 个暴露的局限"之一，
而且是**结构性**的：不是规则写得不够多，是**判据类型缺失**——签名匹配只能看
"请求里有什么词"，看不出来"同一个 IP 在 5 分钟内试了 500 个账号"。后者要阈值
规则 + 响应码，属于另一套判据体系。把这条讲清楚，比报一个漂亮的总检出率更有价值。

> 注：以上"能测"指**判据设计上覆盖**，不等于"实测一定命中"。真实数字必须等
> 数据跑出来，这里不做任何预估——预估本身就是一种编造。


## 4. 复现方式

```bash
# 1) 自检（不需要任何数据集，10 秒）
python bench/run_benchmark.py --self-test

# 2) 真实数据（先切一段 200 MB 跑通，别直接上 7.7 GB）
editcap -c 200000 Thursday-WorkingHours.pcap data/thu_200k.pcap
python bench/run_benchmark.py \
    --pcap data/thu_200k.pcap \
    --labels bench/labels/cic_ids2017_thursday_web.json \
    --out out/

# 3) 跑全量
python bench/run_benchmark.py \
    --pcap data/Thursday-WorkingHours.pcap \
    --labels bench/labels/cic_ids2017_thursday_web.json \
    --out out/
```

产物：

- `out/bench_<name>.csv`：逐请求明细（ts / src_ip / uri / 期望 / 命中规则 / TP-FN-FP-TN）
- `out/bench_<name>_report.md`：混淆矩阵 + 三个数 + 分攻击类型 + 标注灰色地带

## 5. 引用与合规

- CIC-IDS2017：Sharafaldin, Lashkari, Ghorbani, *Toward Generating a New Intrusion
  Detection Dataset and Intrusion Traffic Characterization*, ICISSP 2018.
  使用遵循 CIC 的研究用途要求。
- 攻击时段与攻击者 IP 的公开出处：MDPI *Early-Stage Detection of Cyber Attacks*
  (2020) Table 4。
- 自己抓的流量只抓自己的主机与自己的网络。
