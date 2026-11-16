# 命令注入判据的取舍曲线：四个点、一条结论

- 生成方式：手工整理，数字全部来自下方「复现」小节里的四条命令，未估算
- 语料：CIC-IDS2017 三份全量良性流量 **150,262 条**（误报侧）+ OWASP CRS 回归集 **1,940 条**攻击样本（检出侧）
- 读这份报告的前置：先读 [`crs_regression.md`](crs_regression.md) §5，那里解释了「CRS 判危险词、本项目判语法结构」

> **这份是 v2.4 的决策记录，表内数字保留 v2.4 当时的状态。**
> v2.5 只改判据视图（未声明 `Content-Type` 的 body 里 `+` 还原成空格），
> **规则一条没加**，同一套语料上的基线从 313 变成 **359/1,940 = 18.5%**。
> 表里四个候选都是**同一基线之上的增量**（每个只加载自己一条规则），
> 相对大小与结论不变；当前绝对值见 [`crs_regression.md`](crs_regression.md)
> 与 [`BENCHMARK.md`](../BENCHMARK.md) §2.15。

## 1. 结论

v2.3 把 CRS 全量样本跑完，得到 16.1%。漏检归因里 **328 条集中在命令注入**，其中
**84.1% 压根没有注入语法**——只是参数里出现了一个命令词。

于是问题变成：**「参数里出现命令词」这件事，值不值得为它开一条判据？**

答案不是「值」或「不值」，是一条曲线。四个候选判据，同一套语料，同一套分母：

| 判据 | 判据形态 | CRS 检出 | 增益 | CIC 真误报 | 真误报/10万 | 决定 |
|---|---|---:|---:|---:|---:|---|
| 基线 v2.3 | 语法（分隔符 / `$()` / 反引号） | 313 | — | — | — | 已在线上 |
| `http-cmdline-in-param` | **语法**（命令行形状：命令名 + 选项/路径） | **335** | **+22** | **0** | **0.00** | **上线（v2.4）** |
| `http-bare-command-narrow` | 词表（只留不像自然词的命令名） | 331 | +18 | 33 | 21.96 | 否 |
| `http-bare-command-in-param` | 词表（全量命令名） | 356 | +43 | 80 | 53.24 | 否 |
| `http-windows-batch-loop` | 语法（`FOR`/`IF` 语句形状） | 363 | +50 | 0 | 0.00 | 证据不足，留 `proposed/` |

**一句话**：词表口径越宽，多抓的样本越多，误报按同一比例涨；**换成语法口径之后，
两个轴同时变好**——`cmdline` 比窄版词表多抓 4 条、误报从 33 条变成 0 条。

这是「判据要描述形状、不要枚举写法」那条方法论的第四次兑现，而且这次是在
**没有修改任何已有判据**的前提下兑现的：它没有把某个漏检变成检出，而是补上了
一个此前完全没有判据的**语法位置**。

## 2. 增益是三条判据各自独立的，不是同一条样本数了三遍

    313（基线） + 43（bare 宽） + 50（batch） = 406（合测实测）
    313（基线） + 22（cmdline） + 50（batch） = 385（合测实测）

两组都一位不差。这说明三条判据抓的是**互不相交**的样本——它们补的是三个
不同的语法位置，不是同一条载荷数了三遍。

误报侧也不重叠：`batch` 贡献 0 条，所以合测的 80 条全部来自 `bare` 宽版。

## 3. 两个词表版为什么失败——不是词选得不好

把宽版在 150,262 条良性请求上的 80 条命中按**实际命中的片段**聚类，
只有 6 个短语：

| 命中片段 | 条数 | 样本 |
|---|---:|---|
| `=source+` | 40 | `/css?family=Source+Sans+Pro:300,...`（Google Fonts 字体名） |
| `=source ` | 21 | 同上，字体文件的 `Referer` |
| `=java ` | 9 | `&p=java deployment toolkit 8.0.13`（Java 版本探测串） |
| `=ex ` | 5 | `&dr=367&ty=ex HTTP/1.1` |
| `=id+` | 4 | `/f?P4=ID%2b9mlPql...`（`%2b` 解出的 `+`） |
| `=ping ` | 1 | `&et=ping HTTP/1.1`（统计像素的 `et` 参数） |

看起来是「`source` / `ping` / `id` 这些词太常见」。**但真实机制不是词汇重叠**：

- `=ex ` 与 `=ping ` 后面的那个空格，是**请求行自己的 ` URI HTTP/1.1` 分隔符**。
  请求行以 ` HTTP/1.1` 结尾，所以 `normalized` 里恒有一个空格紧跟在 URI 之后。
- `=id+` 的 `+` 是 `%2b` 解码出来的，它冒充了「命令名到此结束」。

也就是说，判据里那个 `(?:%20|\+| |$)` 想表达「命令名后面是空白或行尾」，
而**这个边界条件在 HTTP 里几乎恒成立**。词表越宽，落在这些位置上的常见词越多，
误报就越多——`source`、`java`、`id`、`ping`、`ex` 只是恰好站在那儿的词。

窄版（只留带数字/长而罕见的命令名）把误报压到 33 条，可这 33 条**全部来自
同一个用户搜 "nmap"**：

```
/complete/search?client=heirloom-serp&pq=nmap&cp=5     ← 搜索联想接口
/vi/sytySTfuMxs/default.jpg?h=90&w=120                 ← 缩略图，Referer 带 =nmap+
```

它压下来的不是「判据更准」，是「`nmap` 恰好是个罕见词」。换一份语料，
下一次有人搜 `ansible` / `kubectl` / `docker`，这 33 条就会以另一个词重新出现。

## 4. 第三个点为什么过线：把边界从「结束」改成「参数」

`http-cmdline-in-param` 不收「命令名后面是空白或行尾」，它要求**命令名后面紧跟
选项（`-sV` / `--version`）或路径（`/etc/passwd`）**：

```yaml
'[=&](?:%20|\+| ){0,3}(?:/bin/|/usr/bin/|...)?(?:gunzip|base64|nmap|perf|...|cat|ls|bash|...)
 (?:%20|\+| )+(?:-{1,3}[a-z]|/)'
```

对上面前 5 个误报短语逐个复核：

| 片段 | 命令名后面是什么 | 结果 |
|---|---|---|
| `=source+` | `Sans` | 不命中 |
| `=source ` | `Sans` | 不命中 |
| `=java ` | `deployment` | 不命中 |
| `=ex ` | `HTTP/1.1` | 不命中 |
| `=id+` | `9ml` | 不命中 |
| `=ping ` | `HTTP/1.1` | 不命中 |

而基准里的真载荷全部满足：

```
code=cat+%2Fetc%2Fsubuid                          → cat + /etc/...
cmd=/bin/gunzip -c /var/log/something_sensitive.gz → gunzip + -c
args=perf --version                                → perf + --version
cmd=bash%20-c%20%22echo%20test%22                  → bash + -c
932130-22=ls%20%2Fa%5Bb%2F%2F%2F%5Dc               → ls + /a...
```

22 条新增检出的完整清单可从 `bench/run_crs_bench.py` 的产物里逐条复现，
**全部是命令行形态的真载荷**，没有一条是判据碰巧命中的。

另外它在 CRS 自称「不该触发」的 563 条样本上只多命中 1 条，而那 1 条是
`932260-1=bash -c "echo test"`——本身就是一条命令行，属 `undocumented` 桶
（CRS 没写 `desc`），不是判据过宽的证据。

## 5. 上线决定

**上线 `http-cmdline-in-param`（severity: high，signature/threshold=1）。**

| 项 | 变化 |
|---|---|
| 规则数 | 30 → **31**（Sigma 导出 27 → **28**） |
| 主矩阵（CIC 三份全量） | TP 857 / FP 45 / TN 150,217；**真实误报 4/150,262 不变** |
| 真实流量上新增检出 | **0**（8,925 条攻击窗请求里一条也没有命令注入） |
| CRS 全量 | 313 → **335**（16.1% → 17.3%） |
| 命令注入漏检 | 328 → **306** |

第 3 行必须写出来：**这条判据在唯一有真实攻击标注的语料上一分没涨**。
CIC 的攻击流量是 XSS / SQLi / 爆破，没有命令注入——所以它在真实流量上的价值
只能等真实出现过一次才知道。它上线的依据是「0 误报 + 第三方的 22 条真载荷」，
不是「真实流量上抓到了什么」。

**没上线的两个词表版**：挪到 `bench/proposed/`，文件头写了各自的代价，
`tests/test_rce_ssrf_rules.py::test_rejected_command_candidates_stay_out_of_rules`
正面挡着，防止有人看到 `proposed/` 里的 YAML「怎么没生效」就搬进 `rules/`。

## 6. `http-windows-batch-loop` 为什么也不算过线

它是四个点里 CRS 增益最大的（+50），形态也是语法的（`for ... in (` 循环头、
`if exist X:\` / `if errorlevel N`），WINDOWS 上 0 误报。三条都成立，仍然不进 `rules/`：

**它测出来的 0 误报，是在 Linux 语料上测的。** CIC-IDS2017 是企业办公网流量，
几乎不可能出现 `for /f ... in (` 这种 batch 语句——这个 0 只证明
「不会在 Linux 流量上误报」，**不能证明「不会误报」**。

项目合入线的原话是「真误报必须是 0」。这条规则目前满足的是
「在错的语料上测出来是 0」。解锁条件写在这里：

1. 一份 Windows/IIS 的正常业务流量（哪怕只有几万条请求）；
2. 在上面跑 `bench/run_rule_cost.py`，真误报 0；
3. 两者都满足，`+50` 的增益才第一次有资格被计入。

在此之前它留在 `proposed/`，锁定测试同上。

## 7. 边界

- **搜索/文档流量会命中 `cmdline`**：`?q=cat -A /etc/hosts`、`?q=tar -xzf ...`
  都会命中。CIC 里没有搜索引擎查询，所以 15.0 万条上的 0 误报**覆盖不到这个形状**。
  `severity` 定 high 而不是 critical 就是因为这一类需要看上下文。
  测试 `test_search_query_with_flags_is_a_known_boundary` 钉住这个事实。
- **子命令形态不认**：`q=docker exec -it web sh` 不命中——判据要求命令名后紧跟
  选项或路径，`exec` 属于子命令。要认它得维护「容器 CLI 及其子命令」的词表，
  那是会随上游版本变的东西。CRS 语料里没有这类样本，所以没有实际漏检代价。
- **「0 误报」的口径**：两处 0 都指「CIC-IDS2017 三份全量 150,262 条良性标注
  请求上 0 条」。这不是「在互联网上 0 误报」，也不是「在任何语料上 0 误报」。

## 8. 复现

```bash
# 1) 基线与新判据的误报（同一份缓存，15.9 万请求，约 25 秒）
python bench/run_rule_cost.py                      # 基线：4 条真误报，全部来自 XSS
python bench/run_rule_cost.py --only cmdline       # 新判据：0 条

# 2) 两个词表版的代价（规则文件在 bench/proposed/，需先拷进临时目录）
python bench/run_rule_cost.py --rules <只含宽版规则的目录> --only bare-command
python bench/run_rule_cost.py --rules <只含窄版规则的目录> --only bare-command-narrow
python bench/run_rule_cost.py --rules <只含batch规则的目录> --only windows-batch

# 3) CRS 全量检出（逐字节可复现，约 40 秒）
python bench/run_crs_bench.py --out bench/results/crs_regression.md

# 4) 四个点的对照（把某个候选规则目录喂进去，看 detected）
python bench/run_crs_bench.py --rules <候选规则目录> --json
```
