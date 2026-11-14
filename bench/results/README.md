# 评测报告存档

这三份是 `bench/run_benchmark.py` 在 CIC-IDS2017 三份**全量**抓包上直接产出的
报告原文，未手工改动数字。放在仓库里是为了让 `BENCHMARK.md` 里的每个结论
都能被 clone 下来的人逐条复核。

| 文件 | 数据集 | 主要结论 |
|---|---|---|
| `cic_ids2017_monday.md` | 周一（零攻击工作日） | 54,732 请求，FP 3，误报率 0.0055% |
| `cic_ids2017_tuesday.md` | 周二（FTP/SSH 爆破日） | 48,345 请求，FP 0，误报率 0.0000% |
| `cic_ids2017_thursday.md` | 周四（Web 攻击日） | 56,110 请求，TP 853 / FN 8,072 / FP 42 / TN 47,143；含分母构成、误报归因、敏感性区间 |

下面三份由 `bench/run_frequency.py` 产出（v1.7），是**告警（窗口）级**评测，
与上面的逐请求矩阵**不能相加**，见 [`BENCHMARK.md`](../BENCHMARK.md) §2.6：

| 文件 | 数据集 | 主要结论 |
|---|---|---|
| `cic_ids2017_monday_frequency.md` | 周一（全良性，阈值标定） | 54,732 请求 / 64 条登录请求，60s 良性峰值 **4**，0 告警 |
| `cic_ids2017_tuesday_frequency.md` | 周二（全良性，阈值标定） | 48,345 请求 / 57 条登录请求，60s 良性峰值 **4**，0 告警 |
| `cic_ids2017_thursday_frequency.md` | 周四（攻击日，检出验证） | 60s 攻击峰值 **153**；8 条窗口告警全部 TP、0 FP，Brute Force 窗覆盖 1/1 |

下面这份由 `bench/run_crosscheck.py` 产出（v1.8），是**跨项目交叉评测**：
拿 `bypasslab` 的攻击语料打本项目的签名规则。它既不是真实数据集、也不含窗口
告警，口径与前两组都不同，见 [`BENCHMARK.md`](../BENCHMARK.md) §2.8：

| 文件 | 语料 | 主要结论 |
|---|---|---|
| `crosscheck_bypasslab.md` | bypasslab 228 条（含 OWASP CRS 59 条第三方基准、冻结 holdout 19 条） | 检测范围内 58/117 = **49.6%**（SQli 32.0% / XSS 62.5% / 路径遍历 65.0% / 反序列化 60.0%）；良性 36 条误报 1 条；RCE / SSRF / 扫描器指纹 75 条记为能力缺口、不进分母 |

> 这份报告的作用不是给检测器打分，而是**定位规则烂在哪一层**：它把
> 「归一化缺口（`+` 未解码）」和「规则覆盖缺口」分开量化了。

## 为什么只有报告，没有逐请求 CSV

`out/bench_*.csv` 是逐请求明细，三份合计约 21 MB，包含数据集里的真实 URI 与
主机头。它们由 `.gitignore` 排除，不进仓库——需要的人用下面的命令自己生成，
比下载一个可能过期的二进制产物更可靠：

```bash
python bench/run_benchmark.py --pcap <pcap> \
    --labels bench/labels/<对应标注>.json --out out/
```

标注文件在 `bench/labels/`，偏移与攻击源 IP 的实测依据写在各文件的
`_offset_evidence` / `_attacker_ip_note` 字段里。

## 报告里的路径

报告首行保留了运行时的 PCAP 绝对路径（本机 `D:\Downloads\` 与 `data/`），
这是脚本如实打印的，不是配置要求。换任何路径都能复现，只要文件字节一致。

复现命令、口径定义与局限清单见 [`BENCHMARK.md`](../BENCHMARK.md)。
