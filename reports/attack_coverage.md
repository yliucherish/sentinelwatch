# SentinelWatch ATT&CK 覆盖报告

> 本文件由 `tools/attack_coverage.py` 生成，请勿手改。覆盖率从规则文件的 `attack.*` 标签动态统计。

## 覆盖率（两种口径）

| 口径 | 覆盖 | 总数 | 覆盖率 | 看的是什么 |
|---|---|---|---|---|
| 子技术层 | 6 | 15 | 40.0% | 判据是否细化到子技术 |
| 父技术层 | 5 | 10 | 50.0% | 攻击场景是否齐全 |

**分母定义**：三个数据源（认证日志 / 应用日志 / HTTP 流量）+ FIM 在原理上能看见的技术。不是全量 ATT&CK 矩阵——那个分母下任何单点项目都不到 1%，数字没有改进意义。

## 明细

| 技术 | 名称 | 战术 | 状态 | 对应规则 |
|---|---|---|---|---|
| T1110 | Brute Force | credential-access | ✅ 已覆盖 | ssh-brute-force |
| T1110.001 | Password Guessing | credential-access | ✅ 已覆盖 | ssh-brute-force |
| T1110.003 | Password Spraying | credential-access | ⬜ 未覆盖 | — |
| T1110.004 | Credential Stuffing | credential-access | ⬜ 未覆盖 | — |
| T1078 | Valid Accounts | defense-evasion | ⬜ 未覆盖 | — |
| T1087 | Account Discovery | discovery | ✅ 已覆盖 | ssh-user-enumeration |
| T1087.001 | Local Account | discovery | ⬜ 未覆盖 | — |
| T1046 | Network Service Discovery | discovery | ⬜ 未覆盖 | — |
| T1190 | Exploit Public-Facing Application | initial-access | ✅ 已覆盖 | fastjson-jdbcrowset-payload, fastjson-cache-bypass, fastjson-expectclass-bypass, fastjson-jndi-url-in-input, fastjson-jndi-trigger-trace, fastjson-module-blocked, http-log4shell-jndi, http-fastjson-autotype, log4shell-jndi-payload, log4shell-jndi-obfuscated, log4shell-jndi-ldapctx-residue, log4shell-jndi-deserialized |
| T1059 | Command and Scripting Interpreter | execution | ✅ 已覆盖 | http-webshell-body-markers |
| T1059.004 | Unix Shell | execution | ⬜ 未覆盖 | — |
| T1505.003 | Web Shell | persistence | ✅ 已覆盖 | http-webshell-body-markers |
| T1071.001 | Web Protocols | command-and-control | ⬜ 未覆盖 | — |
| T1041 | Exfiltration Over C2 Channel | exfiltration | ⬜ 未覆盖 | — |
| T1565.001 | Stored Data Manipulation | impact | ⬜ 未覆盖 | — |

## 未覆盖项与补法（backlog）

| 技术 | 名称 | 需要补什么 |
|---|---|---|
| T1110.003 | Password Spraying | 加"横向"判据：按 IP 聚合后统计 distinct(username) ≥ N 且单账户失败次数低于爆破阈值——现有规则只按 IP 计数，喷一个账户和喷一百个账户出来的数一样 |
| T1110.004 | Credential Stuffing | 接外部泄露凭据情报（HIBP / 内部 IOCs 库）做账号比对；纯日志侧无法区分"撞库成功"和"用户打错密码" |
| T1078 | Valid Accounts | 需登录成功的行为基线（首见的主机/时段/源段组合），当前没有历史行为建模，任何 accepted_password 都看着一样 |
| T1087.001 | Local Account | 检测能力已具备（ssh-user-enumeration 就是这条），只差在规则上补attack.t1087.001 标签——属于标注粒度问题，不是能力缺失 |
| T1046 | Network Service Discovery | 解析器目前只提取完整 HTTP 事务，需加"SYN 发出后无三次握手"的半开连接统计，才能识别端口扫描 |
| T1059.004 | Unix Shell | 在 webshell 规则里补 shell 元字符判据（/bin/sh、bash -c、$( |
| T1071.001 | Web Protocols | 需 beacon 周期检测：同一 URI 等间隔请求的间隔方差分析——这是时序统计，与现有"子串匹配"完全不同的判据类型 |
| T1041 | Exfiltration Over C2 Channel | 解析器丢弃了服务端响应体，需保留响应字节数并按源 IP 聚合出站量，再对"单会话出站远超入站"设阈值 |
| T1565.001 | Stored Data Manipulation | FIM 已能报"文件变了"，但没接成 ATT&CK 判据也没打标签；需把被改路径限定到关键配置/二进制目录才能算这条 |

## 明确不在范围

| 技术 | 名称 | 为什么不做 |
|---|---|---|
| T1055 | Process Injection | 需要 EDR 的内存/进程回调视图，三个数据源都看不到 |
| T1003 | OS Credential Dumping | 需要主机侧进程访问 / 内存读取 |
| T1547 | Boot or Logon Autostart Execution | 需要注册表或 systemd 单元的写入监控 |
| T1486 | Data Encrypted for Impact | 需要文件熵值/批量改写检测，FIM 只能报单文件变更 |
| T1566 | Phishing | 邮件网关不在这套数据源里 |
| T1552 | Unsecured Credentials | 需要主机文件系统读取权限 |
