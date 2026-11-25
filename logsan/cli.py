"""命令行入口：

  python -m logsan sanitize   直接清洗参数/标准输入文本
  python -m logsan collect    采集管道：多格式行 -> 统一 JSON 信封
  python -m logsan safe-cat   安全查看遗留日志（不改原文件，附带告警）
  python -m logsan search     生成检索特征的转义形态/迁移期正则
  python -m logsan decode     取证：把转义记号还原成原始 payload
"""

from __future__ import annotations

import argparse
import sys

from .collect import process_line
from .encoding import BackslashXEncoder, ControlPictureEncoder
from .policy import Policy, sanitize
from .query import encode_search_term, grep_regex
from .view import print_report, render_stream

_ENCODERS = {
    "backslash-x": BackslashXEncoder,
    "control-picture": ControlPictureEncoder,
}


def _policy_from_args(args: argparse.Namespace) -> Policy:
    encoder_cls = _ENCODERS[args.encoder]
    return Policy(
        allow_tab=args.allow_tab,
        allow_sgr=args.allow_sgr,
        escape_bidi=not args.keep_bidi,
        escape_zero_width=not args.keep_zero_width,
        encoder=encoder_cls(),
    )


def _open_input(path: str | None):
    if path and path != "-":
        # newline="" 保留原始换行符，交给渲染层决定如何展示
        return open(path, "r", encoding="utf-8", errors="surrogateescape",
                    newline="")
    return sys.stdin


def cmd_sanitize(args: argparse.Namespace) -> int:
    policy = _policy_from_args(args)
    if args.text:
        print(sanitize(args.text, policy).text)
        return 0
    for line in _open_input(args.file):
        result = sanitize(line.rstrip("\r\n"), policy)
        print(result.text)
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    policy = _policy_from_args(args)
    source = args.source or (args.file or "stdin")
    infile = _open_input(args.file)
    try:
        # 用记录聚合迭代器：含嵌入换行的单条 JSON 不会被物理行拆散
        from .collect import iter_records
        for record_text in iter_records(infile, fmt=args.format):
            envelope = process_line(
                record_text, source=source, fmt=args.format, policy=policy
            )
            print(envelope.to_json())
    finally:
        if infile is not sys.stdin:
            infile.close()
    return 0


def cmd_safe_cat(args: argparse.Namespace) -> int:
    policy = _policy_from_args(args)
    infile = _open_input(args.file)
    try:
        report = render_stream(
            infile, sys.stdout, policy=policy,
            color=None if args.color == "auto" else args.color == "always",
            with_lineno=not args.no_lineno,
        )
    finally:
        if infile is not sys.stdin:
            infile.close()
    if not args.quiet:
        print_report(report)
    return 1 if report.high_severity and args.fail_on_high_risk else 0


def cmd_search(args: argparse.Namespace) -> int:
    policy = _policy_from_args(args)
    if args.grep:
        print(grep_regex(args.term, policy))
    else:
        print(encode_search_term(args.term, policy))
    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    encoder = _ENCODERS[args.encoder]()
    if args.text:
        sys.stdout.write(encoder.decode(args.text) + "\n")
        return 0
    for line in _open_input(args.file):
        sys.stdout.write(encoder.decode(line.rstrip("\r\n")) + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsan",
        description="终端控制字符注入防护：写入/采集/查看三层工具",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--encoder", choices=list(_ENCODERS),
                        default="backslash-x", help="可逆编码器（默认反斜杠记号）")
    common.add_argument("--allow-tab", action="store_true", help="保留水平制表符")
    common.add_argument("--allow-sgr", action="store_true",
                        help="放行严格校验过的 SGR 颜色序列")
    common.add_argument("--keep-bidi", action="store_true",
                        help="保留双向排版控制字符（默认转义）")
    common.add_argument("--keep-zero-width", action="store_true",
                        help="保留零宽字符（默认转义）")

    p_san = sub.add_parser("sanitize", parents=[common],
                           help="清洗文本（参数或 stdin）")
    p_san.add_argument("text", nargs="?", help="直接传入的文本；省略则读 stdin")
    p_san.add_argument("-f", "--file", help="输入文件，- 表示 stdin")
    p_san.set_defaults(func=cmd_sanitize)

    p_col = sub.add_parser("collect", parents=[common],
                           help="采集管道：每行输出一个 JSON 信封")
    p_col.add_argument("-f", "--file", help="输入文件，- 表示 stdin")
    p_col.add_argument("--source", help="来源标识，写入信封 source 字段")
    p_col.add_argument("--format", choices=["auto", "json", "syslog", "plain"],
                       default="auto", help="输入格式（默认自动探测）")
    p_col.set_defaults(func=cmd_collect)

    p_cat = sub.add_parser("safe-cat", parents=[common],
                           help="安全查看遗留日志")
    p_cat.add_argument("file", nargs="?", help="日志文件；省略则读 stdin")
    p_cat.add_argument("--color", choices=["auto", "always", "never"],
                       default="auto")
    p_cat.add_argument("--no-lineno", action="store_true", help="不显示行号")
    p_cat.add_argument("--quiet", action="store_true", help="不输出汇总报告")
    p_cat.add_argument("--fail-on-high-risk", action="store_true",
                       help="发现高危序列时退出码为 1（便于接入巡检）")
    p_cat.set_defaults(func=cmd_safe_cat)

    p_search = sub.add_parser("search", parents=[common],
                              help="检索特征编码与迁移期正则")
    p_search.add_argument("term", help="原始检索特征（可含控制字符）")
    p_search.add_argument("--grep", action="store_true",
                          help="输出 grep -E 可用的双形态正则")
    p_search.set_defaults(func=cmd_search)

    p_dec = sub.add_parser("decode", help="取证：还原转义记号")
    p_dec.add_argument("text", nargs="?")
    p_dec.add_argument("-f", "--file")
    p_dec.add_argument("--encoder", choices=list(_ENCODERS),
                       default="backslash-x")
    p_dec.set_defaults(func=cmd_decode)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
