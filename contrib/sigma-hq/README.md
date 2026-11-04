# SigmaHQ PR 材料

> 目标仓库：https://github.com/SigmaHQ/sigma
> 目标目录：`rules/web/webserver_generic/`
> 状态：**分支已备好，等一次 Fork 点击**（本地分支 `add-fastjson-autotype-rules`，
> 基于上游 `c68bb91`，一次 `git push` 即可推上 fork）

## 一、为什么是 Fastjson，而不是 Log4Shell / SQLi / XSS

先做了上游调研（2026-11-04，`git/trees?recursive=1` 拉全量 4557 个 `.yml` 路径后按关键词检索）：

| 关键词 | 上游命中 | 结论 |
|---|---|---|
| `fastjson` | **0** | ← 空白 |
| `autotype` | **0** | ← 空白 |
| `deserial` | **0** | ← 空白 |
| `jndi` | 2（`web_jndi_exploit` / `java_jndi_injection_exploitation_attempt`） | 已覆盖 |
| `webshell` | 5 | 已覆盖 |
| `sql_injection` | 1 | 已覆盖 |
| `xss` | 1 | 已覆盖 |
| `path_traversal` | 4 | 已覆盖 |

也就是说：SentinelWatch 那 20 条可导出规则里，**绝大多数都是重复造轮子**——JNDI、SQLi、XSS、
路径遍历、WebShell 上游都有。真正不撞车的只有 Fastjson 那 6 条。

这个结论本身值得记住：**"我写了 20 条规则"和"我能给上游补空白"是两件事。**
盲目提 PR 的结果大概率是被人贴一个已存在规则的链接然后 close。

顺带确认一条容易误判的：`web_jndi_exploit.yml` 看着像 Log4Shell，实际查内容是对
**JNDI-Exploit-Kit 的 URL 路径**（`/Basic/Command/Base64/` 这类），与 Fastjson 的
`@type` 载荷无关，不构成重复。

## 二、提交什么

两条，覆盖 Fastjson 两条主要利用链：

| 文件 | 覆盖 | 级别 | UUID |
|---|---|---|---|
| `web_fastjson_autotype_jndi.yml` | `@type` → `com.sun.rowset.JdbcRowSetImpl`（JNDI 链，CVE-2022-25845 及同类绕过） | critical | `e32a067f-...` |
| `web_fastjson_autotype_bypass.yml` | `@type` → `java.lang.Class`（1.2.25–1.2.47 缓存绕过）/ `java.lang.AutoCloseable`（1.2.48–1.2.68 expectClass 绕过） | high | `7c45d854-...` |

**为什么只提两条不提六条**：PR 越小越好 review。六条一次性砸过去，reviewer 的
心理负担会直接变成 "please split this"。剩下四条（`expectClass`、`jndi-url-in-input`、
`jndi-trigger-trace`、`module-blocked`）等这个 PR 有反馈再说。

## 三、规则怎么写（设计说明，review 时会问）

```yaml
logsource:
    category: webserver
detection:
    selection_autotype:
        - '@type'
        - '%40type'
    selection_gadget:
        - 'com.sun.rowset.JdbcRowSetImpl'
    condition: selection_autotype and selection_gadget
```

四个刻意的决定：

1. **用 `keywords`（无字段全文本）而不是 `cs-uri-query`**：Fastjson 的 payload 通常在
   POST body 里，而多数 access log 只记 URI 不记 body。用 `keywords` 至少能在"日志里带了
   body"或"payload 放在 GET 参数/JSONP 回调里"两种情况下命中；写死 `cs-uri-query`
   会把后者也漏掉。
2. **两个 selection 相 `and`，而不是把整串 `"@type":"com.sun.rowset.JdbcRowSetImpl"` 当一个
   keyword**：JSON 里 `@type` 与类名之间可以有空格、换行、转义、字段顺序变化。
   写整串看着精确，实际脆得一碰就漏——**这类"看着更严格其实更漏"的判据是签名规则最常见的坑**。
3. **不加 `filter`**：正常业务里 `@type` 与 `JdbcRowSetImpl` 同现的概率极低，
   提前加 filter 只会削弱检出。误报面写进 `falsepositives` 说明即可。
4. **`@type` 同时匹配原文与 URL 编码 `%40type`**：这一条是照上游
   `web_java_payload_in_access_logs.yml` 的写法学的——那条规则把
   `'${(#a=@'` 和 `'%24%7B%28%23a%3D%40'` 并列，因为同一个载荷经 URL 传参时
   在日志里就是编码形态。只写原文会漏掉"payload 走 query string"这一整类。

## 四、提交前本地校验

```bash
sigma check -x attacktag contrib/sigma-hq/
# Found 0 errors, 0 condition errors and 0 issues.
```

> `-x attacktag` 是因为 `sigma check` 默认要联网拉 MITRE ATT&CK 数据校验 tag；
> 当前网络下这一步会超时。其余校验（语法、condition 引用、字段修饰符）照常执行。

## 五、PR 标题与描述

**标题**

```
Add rules for Fastjson autoType deserialization payloads
```

**描述**

```markdown
## What this PR does

Adds two web/webserver_generic rules for Fastjson autoType deserialization payloads:

- `web_fastjson_autotype_jndi.yml` — `@type` pointing at `com.sun.rowset.JdbcRowSetImpl`,
  the most common gadget for turning Fastjson deserialization into a JNDI lookup.
- `web_fastjson_autotype_bypass.yml` — `@type` pointing at `java.lang.Class` or
  `java.lang.AutoCloseable`, used to slip past the autoType denylist
  (1.2.25–1.2.47 class-cache bypass, 1.2.48–1.2.68 expectClass bypass).

## Why

Fastjson is one of the most widely deployed Java JSON libraries, and its autoType
bypass series (closed in 1.2.83) has been actively exploited. Searching the repo
for `fastjson` / `autotype` / `deserial` currently returns no rules, while JNDI,
SQLi, XSS, path traversal and webshell all have coverage under
`rules/web/webserver_generic/`.

## Detection notes

Both rules use two selections combined with `and` rather than one verbatim string:
JSON field order, whitespace and escaping vary between payloads, so matching
`"@type":"com.sun.rowset.JdbcRowSetImpl"` as a single substring would be brittle.

`keywords` is used instead of a specific field because the payload normally arrives
in a POST body, which many access logs do not record; keeping it field-agnostic at
least covers GET parameters and JSONP callbacks. `@type` is also matched in its
percent-encoded form (`%40type`) for payloads carried in a URI, following the same
approach as `web_java_payload_in_access_logs.yml`.

**Known limitation, stated up front:** a plain Common Log Format line carries only
the URI. These rules therefore need request body logging (ModSecurity/Coraza audit
logs, nginx `$request_body`, Apache mod_dumpio, or a WAF that records POST bodies)
to see the POST-body case. If the maintainers would rather have this as an
application-log rule where the body is always present, I'm happy to move them to
`rules/application/` instead.

## Validation

`sigma check -x attacktag` on both files: 0 errors, 0 condition errors, 0 issues.

## References

- https://github.com/alibaba/fastjson/wiki/security_update_20220523
- https://github.com/alibaba/fastjson/wiki/enable_autotype
- https://nvd.nist.gov/vuln/detail/CVE-2022-25845
```

## 六、提交流程（实际要做的只有第 1 步和第 4 步）

前置工作已经完成：本地分支已建好、提交已按上游 master 打好、`sigma check` 已过。

```bash
# 【你要做的 1】在 https://github.com/SigmaHQ/sigma 点右上角 "Fork"
#                 → Create fork。五秒钟，不需要任何 token。

# 【我来做】2) 把已备好的分支推到你的 fork
cd <这个临时克隆目录>
git remote add fork git@github.com:yliucherish/sigma.git
git push -u fork add-fastjson-autotype-rules

# 【你要做的 3】打开下面这个链接，点 "Create pull request"，粘贴第五节的描述
#   https://github.com/SigmaHQ/sigma/compare/master...yliucherish:add-fastjson-autotype-rules
```

为什么不用 token：本机 SSH key 已验证可推（`ssh -T git@github.com` 返回
`Hi yliucherish!`），HTTPS 反而被代理挡着（`CONNECT tunnel failed, response 502`）。
所以走 SSH + 一次网页 Fork 是最短路径，**不需要把 PAT 交给我**。

## 七、诚实的预期管理

- **等 1–2 周是正常的**，被要求改也是正常的（很可能被要求：加 `modified` 字段、
  归到不同目录、或改成 `cs-uri-query` + `cs-method` 的组合）。
- **被拒也可能**，理由大概率是"webserver 日志看不到 body，检测不可靠"。
  这个质疑本身是对的——所以我在 `falsepositives` 和 PR 描述里都先说明了这个限制。
  如果被这样拒，改法是转去 `rules/application/`（JVM 应用日志场景），
  那时 body 一定在日志里。
- **没 merge 就是没 merge**。简历只能写「向 SigmaHQ 提交检测规则 PR（链接）」，
  不能写"已被采纳"。**提交本身是能力证明，merge 是加分不是必需。**
