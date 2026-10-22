"""v1.0 组件测试：告警报告导出（report.py）。

覆盖：
1. 全链路：导入样本日志 → 出告警 → 导出报告 → 核心区块齐全
2. XSS 安全：恶意字段（告警标题/IP）必须被转义——报告生成器自己不能是注入载体
3. 图表：服务端 SVG（折线/柱状）真实产出
4. 空库：无告警时报告依然完整可用（交付物不能崩）
5. 自包含：零外部引用、零 JS（内网隔离环境约束）
6. 打印适配：@media print / @page 存在（Ctrl+P 存 PDF 的前提）
7. CLI：report 子命令端到端
"""
from datetime import datetime
from pathlib import Path

import pytest

from cli import main
from collectors.auth_log import parse_file
from engine.detector import load_rules_dir, run_rules
from models import Alert
from report import build_report_data, export_report, render_html
from storage import Storage

_ROOT = Path(__file__).parent.parent
_SAMPLE_LOG = Path(__file__).parent / "sample_auth.log"
_RULES_DIR = _ROOT / "rules"


@pytest.fixture()
def db_with_alerts(tmp_path):
    """用样本日志造一个含 2 条告警（暴力破解 HIGH + 用户名枚举 MEDIUM）的库。"""
    db = tmp_path / "sentinelwatch.db"
    events = parse_file(_SAMPLE_LOG)
    alerts = run_rules(events, load_rules_dir(_RULES_DIR))
    storage = Storage(db)
    try:
        storage.insert_events(events)
        storage.insert_alerts(alerts)
    finally:
        storage.close()
    return db


@pytest.fixture()
def empty_db(tmp_path):
    """有库（建好 schema）但无告警——与"库文件不存在"是两种不同状态：
    后者应报错提示先导入（与 serve 子命令一致的 UX），前者应正常出空报告。"""
    db = tmp_path / "empty.db"
    storage = Storage(db)
    storage.close()
    return db


# ================= 全链路 =================

def test_report_full_flow(db_with_alerts, tmp_path):
    out = export_report(str(db_with_alerts), str(tmp_path / "report.html"))
    html_text = out.read_text(encoding="utf-8")
    # 核心区块一个都不能少（交付物的完整性）
    for fragment in (
        "SentinelWatch",                    # 标题区
        "告警总数",                          # 摘要卡片
        "聚合事件",
        "告警时间线",                        # 图表区
        "TOP 攻击源 IP",
        "SSH 暴力破解",                      # 告警明细（规则名来自样本）
        "SSH 用户名枚举",
        "关联事件",                          # Incident 区块
        "检测规则清单",                      # 可解释性区块
        "请仅用于分析你有权查看的日志",        # 免责声明
    ):
        assert fragment in html_text, f"报告缺少区块: {fragment}"
    # 严重度排序：HIGH 的暴力破解应排在 MEDIUM 的用户枚举之前
    # （在"告警明细"表格区间内断言——分布徽章区不参与排序语义）
    table = html_text.split("告警明细")[1].split("检测规则清单")[0]
    assert table.index("SSH 暴力破解") < table.index("SSH 用户名枚举")
    # 数据源路径回显（可复现：拿到报告的人知道数据从哪来）
    assert "sentinelwatch.db" in html_text


def test_report_title_override(db_with_alerts, tmp_path):
    out = export_report(str(db_with_alerts), str(tmp_path / "r.html"),
                        title="2026-W43 安全运营周报")
    html_text = out.read_text(encoding="utf-8")
    assert "2026-W43 安全运营周报" in html_text
    assert "<title>2026-W43 安全运营周报</title>" in html_text


# ================= XSS 安全 =================

def test_report_escapes_malicious_fields(tmp_path):
    """告警字段可能本身就是攻击载荷（被分析的日志含注入字符串）——
    报告生成器必须转义，否则"生成报告"这个动作自己变成了 XSS。"""
    db = tmp_path / "evil.db"
    storage = Storage(db)
    try:
        storage.insert_alerts([Alert(
            rule_id="xss-test",
            rule_name="<script>alert(1)</script>",
            severity="high",
            title='<img src=x onerror="alert(2)">',
            detail="判定依据 <b>bold</b> ${jndi:ldap://x/}",
            source_ip='1.2.3.4" onmouseover="alert(3)"',
            event_count=3,
            window_start=datetime(2026, 10, 22, 9, 0, 0),
            window_end=datetime(2026, 10, 22, 9, 5, 0),
        )])
    finally:
        storage.close()

    out = export_report(str(db), str(tmp_path / "evil_report.html"))
    text = out.read_text(encoding="utf-8")
    # 转义后存在
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "&lt;img src=x onerror=&quot;alert(2)&quot;&gt;" in text
    assert "onmouseover=&quot;alert(3)&quot;" in text
    # 原始危险形态不存在
    assert "<script>alert(1)</script>" not in text
    assert "<img src=x onerror=" not in text
    assert 'onmouseover="alert(3)"' not in text


# ================= 图表 =================

def test_report_svg_charts_rendered(db_with_alerts, tmp_path):
    out = export_report(str(db_with_alerts), str(tmp_path / "r.html"))
    text = out.read_text(encoding="utf-8")
    assert text.count("<svg") == 2                      # 折线 + 柱状
    assert 'class="line-path"' in text                  # 折线
    assert "<rect" in text                              # 柱状
    assert "linearGradient" in text                     # 蓝→紫渐变面积（配色一致）


# ================= 空库 =================

def test_report_empty_db_still_valid(empty_db, tmp_path):
    out = export_report(str(empty_db), str(tmp_path / "r.html"))
    text = out.read_text(encoding="utf-8")
    assert "暂无告警" in text                            # 图表空态
    assert "暂无告警——先导入日志或执行 FIM 扫描" in text    # 明细表空态
    assert "SSH 暴力破解" in text                        # 规则清单照常附上
    assert "<!DOCTYPE html>" in text                     # 文档依然完整


# ================= 自包含与打印 =================

def test_report_self_contained_and_printable(db_with_alerts, tmp_path):
    out = export_report(str(db_with_alerts), str(tmp_path / "r.html"))
    text = out.read_text(encoding="utf-8")
    # 零外部引用：内网/隔离环境打开不会白屏（与看板同款取舍）
    assert "<script" not in text.lower()
    assert 'src="http' not in text
    assert 'href="http' not in text
    # 打印适配：Ctrl+P 存 PDF 的前提
    assert "@media print" in text
    assert "@page" in text
    assert "print-color-adjust: exact" in text           # 打印保留徽章配色


# ================= 数据层 =================

def test_build_report_data_structure(db_with_alerts):
    data = build_report_data(str(db_with_alerts))
    assert data["stats"]["total_alerts"] == 2
    assert data["stats"]["total_incidents"] >= 1
    assert data["time_range"]["first"] and data["time_range"]["last"]
    # 规则清单 = rules/ 目录全部规则（brute_force 2 条 + log4shell 4 条）
    rule_ids = {r["id"] for r in data["rules"]}
    assert {"ssh-brute-force", "ssh-user-enumeration",
            "log4shell-jndi-payload"} <= rule_ids
    assert data["event_stats"]                           # 原始事件统计
    # 报告侧按严重度排序（与看板的按时间倒序不同——两种消费形态）
    assert [a["severity"] for a in data["alerts"]] == ["high", "medium"]


def test_render_html_is_string(db_with_alerts):
    data = build_report_data(str(db_with_alerts))
    assert isinstance(render_html(data), str)
    assert render_html(data).startswith("<!DOCTYPE html>")


# ================= CLI =================

def test_cli_report_subcommand(db_with_alerts, tmp_path):
    out = tmp_path / "cli_report.html"
    rc = main(["report", "--db", str(db_with_alerts), "--out", str(out)])
    assert rc == 0
    assert out.exists()
    assert "告警总数" in out.read_text(encoding="utf-8")
