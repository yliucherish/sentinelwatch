## What this PR does

Adds two `web/webserver_generic` rules for Fastjson autoType deserialization payloads:

- `web_fastjson_autotype_jndi.yml` — `@type` pointing at `com.sun.rowset.JdbcRowSetImpl`, the
  canonical gadget that turns Fastjson deserialization into a JNDI lookup.
- `web_fastjson_autotype_bypass.yml` — `@type` pointing at `java.lang.Class` or
  `java.lang.AutoCloseable`, the primitives used to slip past the autoType denylist before a
  second-stage gadget is loaded.

## Why

Searching the repo for `fastjson`, `autotype` and `deserial` currently returns no rules, while
JNDI, SQLi, XSS, path traversal and webshell all have coverage under
`rules/web/webserver_generic/`. Fastjson's autoType bypass series — closed in
[1.2.83](https://github.com/alibaba/fastjson/wiki/security_update_20220523) — has been actively
exploited, so this looks like a worthwhile gap to fill.

## Detection notes

Both rules combine two selections with `and` rather than matching one verbatim string: JSON field
order, whitespace and escaping vary between payloads, so `"@type":"com.sun.rowset.JdbcRowSetImpl"`
as a single substring would be brittle.

`@type` is also matched percent-encoded (`%40type`) so payloads carried in a URI are caught too —
same approach as `web_java_payload_in_access_logs.yml`.

**Known limitation, stated up front:** a plain Common Log Format line carries only the URI. These
rules therefore need request body logging (ModSecurity/Coraza audit logs, nginx `$request_body`,
Apache mod_dumpio, or a WAF that records POST bodies) to see the POST-body case. If an
application-log variant under `rules/application/` would be preferred, I'm happy to move them.

## Validation

`sigma check -x attacktag` on both files: 0 errors, 0 condition errors, 0 issues.

## References

- https://github.com/alibaba/fastjson/wiki/security_update_20220523
- https://github.com/alibaba/fastjson/wiki/enable_autotype
- https://nvd.nist.gov/vuln/detail/CVE-2022-25845
