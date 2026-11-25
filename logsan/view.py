"""查看层：遗留日志的安全查看器。

写入层和采集层只能保护“上线之后”产生的日志；磁盘上还有大量历史日志、
以及来不及改造的第三方组件日志。运维直接 ``cat`` 这些文件仍然会中招。
``safe-cat`` 子命令（见 logsan.cli）在打印前即时清洗，并对发现的危险
序列给出告警，本身不修改原文件。

本模块提供可复用的扫描与渲染函数。
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from .ansi import SEVERITY_HIGH, scan_escapes
from .marking import text_prefix
from .policy import FieldStatus, Policy, sanitize

# 终端着色（查看器自己的输出可以用颜色：它是受信进程）
_YELLOW = "\x1b[33m"
_RED = "\x1b[31m"
_DIM = "\x1b[2m"
_RESET = "\x1b[0m"


@dataclass
class ViewReport:
    """单文件/单流的查看报告。"""

    lines_total: int = 0
    lines_flagged: int = 0
    escapes_found: int = 0
    high_severity: int = 0
    details: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.details is None:
            self.details = []


def render_line(line: str, policy: Policy | None = None,
                color: bool = False, lineno: int | None = None) -> tuple[str, ViewReport]:
    """渲染单行：返回 (可安全打印的文本, 该行报告)。

    非破坏式：原始文件不动；输出中的控制字符全部变成可见记号。
    """
    policy = policy or Policy()
    report = ViewReport(lines_total=1)
    stripped_newline = ""
    if line.endswith("\n"):
        stripped_newline = "\n"
        line = line[:-1]

    sequences = scan_escapes(line)
    if sequences:
        report.lines_flagged = 1
        report.escapes_found = len(sequences)
        for offset, seq, info in sequences:
            if info["severity"] == SEVERITY_HIGH:
                report.high_severity += 1
            report.details.append(
                f"line {lineno or '?'} offset {offset}: "
                f"{info['kind']} {info['description']} ({info['severity']})"
            )

    result = sanitize(line, policy)
    prefix = text_prefix(result.status.value)
    shown = result.text
    if prefix:
        label = f"{prefix} "
        if color:
            label = f"{_YELLOW}{label}{_RESET}"
        shown = label + shown

    if color and sequences:
        # 在行尾追加一条红色摘要，提醒运维这一行原本带攻击序列
        hi = sum(1 for _, _, i in sequences if i["severity"] == SEVERITY_HIGH)
        tag = f"  {_RED}<-- {len(sequences)} escape sequence(s), {hi} high risk{_RESET}"
        shown += tag

    if lineno is not None:
        num = f"{lineno:>6}\t"
        if color:
            num = f"{_DIM}{num}{_RESET}"
        shown = num + shown

    return shown + stripped_newline, report


def render_stream(infile, outfile, policy: Policy | None = None,
                  color: bool | None = None, with_lineno: bool = True) -> ViewReport:
    """流式渲染整个文件，汇总报告。默认仅在输出到 TTY 时着色。

    物理行只按 ``\\n`` 切分：嵌入的 ``\\r`` 是攻击者伪造日志行的常用
    手段，必须作为**行内数据**保留并转义，不能让文本迭代器把一条逻辑
    记录拆成两行（否则行号错乱、伪造内容看起来像独立日志行）。
    """
    if color is None:
        color = bool(getattr(outfile, "isatty", lambda: False)())
    total = ViewReport()
    buffer = ""
    lineno = 0
    while True:
        chunk = infile.readline()
        if chunk == "":
            if buffer:
                lineno += 1
                shown, report = render_line(
                    buffer, policy=policy, color=color,
                    lineno=lineno if with_lineno else None,
                )
                outfile.write(shown)
                total.lines_total += report.lines_total
                total.lines_flagged += report.lines_flagged
                total.escapes_found += report.escapes_found
                total.high_severity += report.high_severity
                total.details.extend(report.details)
            break
        buffer += chunk
        # 仅以 \n 作为物理行边界，\r 留在缓冲里交给清洗器
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line + "\n"
            lineno += 1
            shown, report = render_line(
                line, policy=policy, color=color,
                lineno=lineno if with_lineno else None,
            )
            outfile.write(shown)
            total.lines_total += report.lines_total
            total.lines_flagged += report.lines_flagged
            total.escapes_found += report.escapes_found
            total.high_severity += report.high_severity
            total.details.extend(report.details)
    return total


def print_report(report: ViewReport, outfile=sys.stderr) -> None:
    """把汇总报告写到 stderr（不污染 stdout 的日志内容管道）。"""
    if not report.lines_flagged:
        outfile.write(
            f"[logsan] {report.lines_total} line(s) scanned, "
            "no control sequences found.\n"
        )
        return
    outfile.write(
        f"[logsan] {report.lines_total} line(s) scanned, "
        f"{report.lines_flagged} flagged, {report.escapes_found} escape "
        f"sequence(s) neutralized ({report.high_severity} high severity).\n"
    )
    for detail in report.details[:50]:
        outfile.write(f"[logsan]   {detail}\n")
    if len(report.details) > 50:
        outfile.write(
            f"[logsan]   ... {len(report.details) - 50} more, "
            "use the collect pipeline for full detail.\n"
        )
