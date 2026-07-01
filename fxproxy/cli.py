"""fxproxy command-line interface."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from . import config as cfgmod
from .fxa_auth import bootstrap
from .guardian import GuardianClient, NotEnrolledError
from .proxyserver import NodePicker, ProxyServer


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PiB"


def cmd_login(args):
    session_token = args.session_token
    email = args.email
    password = args.password
    if not session_token and email and not password:
        password = getpass.getpass("FxA password: ")
    if not session_token and not email:
        print("provide --session-token, or --email (+ --password)", file=sys.stderr)
        return 2

    print("[*] bootstrapping credentials ...", flush=True)
    res = bootstrap(session_token=session_token, email=email, password=password)
    cfg = cfgmod.load(args.config)
    cfg["refresh_token"] = res["refresh_token"]
    if args.country:
        cfg["country"] = args.country.upper()
    path = cfgmod.save(cfg, args.config)
    q = res["quota"]
    print(f"[+] enrolled uid={q['uid']}  quota={_fmt_bytes(q['max_bytes'])}"
          f"  subscribed={q['subscribed']}")
    print(f"[+] refresh_token saved to {path}")
    print("    (keep this file secret; it grants proxy access to your account)")
    return 0


def cmd_token(args):
    cfg = cfgmod.load(args.config)
    rt = cfg.get("refresh_token")
    if not rt:
        print("no refresh_token; run `fxproxy login` first", file=sys.stderr)
        return 2
    if getattr(args, "quiet", False):
        print(rt)
        return 0
    print("refresh_token (复制到服务器的 config.json 即可，任意 IP 可用):\n")
    print(rt + "\n")
    print("服务器上一次性写入 (Linux/macOS)：")
    print(f'  mkdir -p ~/.config/fxproxy && printf \'{{"refresh_token":"%s","country":"US"}}\''
          " > ~/.config/fxproxy/config.json" % rt)
    print("\n(纯脚本用 `fxproxy token -q` 只输出这一串)")
    return 0


def _client(args) -> GuardianClient:
    cfg = cfgmod.load(args.config)
    if not cfg.get("refresh_token"):
        print("no refresh_token; run `fxproxy login` first", file=sys.stderr)
        raise SystemExit(2)
    return GuardianClient(cfg["refresh_token"])


def cmd_status(args):
    gc = _client(args)
    try:
        q = gc.quota()
    except NotEnrolledError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 3
    print(f"uid              : {q['uid']}")
    print(f"monthly quota    : {_fmt_bytes(q['max_bytes'])}")
    if q.get("remaining_bytes") is not None:
        rem = q["remaining_bytes"]
        used = q.get("used_bytes")
        pct = (100.0 * rem / q["max_bytes"]) if q["max_bytes"] else 0
        print(f"remaining        : {_fmt_bytes(rem)} ({pct:.1f}%)")
        if used is not None:
            print(f"used             : {_fmt_bytes(used)}")
    if q.get("reset"):
        print(f"resets at        : {q['reset']}")
    print(f"subscribed       : {q['subscribed']}")
    print(f"limited_bandwidth: {q['limited_bandwidth']}")
    return 0


def cmd_servers(args):
    gc = _client(args)
    by = gc.nodes_by_country()
    for code in sorted(by):
        print(f"{code}  {by[code]['name']:20} {len(by[code]['nodes'])} node(s)")
    print(f"\n{len(by)} countries")
    return 0


def cmd_run(args):
    cfg = cfgmod.load(args.config)
    if not cfg.get("refresh_token"):
        print("no refresh_token; run `fxproxy login` first", file=sys.stderr)
        return 2
    gc = GuardianClient(cfg["refresh_token"])
    country = (args.country or cfg.get("country") or "").upper() or None
    picker = NodePicker(gc, country)
    srv = ProxyServer(
        gc,
        picker,
        host=args.host or cfg["host"],
        http_port=args.http_port or cfg["http_port"],
        socks_port=args.socks_port or cfg["socks_port"],
        failover=getattr(args, "failover", None) or cfg.get("failover", 3),
    )
    try:
        asyncio.run(srv.serve())
    except KeyboardInterrupt:
        print("\n[fxproxy] 已停止")
    return 0


def cmd_web(args):
    from .webui import run_web
    run_web(
        args.config,
        web_host=getattr(args, "web_host", None) or "127.0.0.1",
        web_port=getattr(args, "web_port", None) or 8765,
        open_browser=not getattr(args, "no_open", False),
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fxproxy",
        description="Standalone landing proxy over Firefox IP Protection (50GB/mo).",
    )
    p.add_argument("-c", "--config", help="config file path")
    # no subcommand -> interactive menu
    sub = p.add_subparsers(dest="cmd", required=False)

    lp = sub.add_parser("login", help="bootstrap credentials (email+pass or sessionToken)")
    lp.add_argument("--email")
    lp.add_argument("--password")
    lp.add_argument("--session-token", help="pre-extracted FxA sessionToken (hex)")
    lp.add_argument("--country", help="default egress country ISO code")
    lp.set_defaults(func=cmd_login)

    sp = sub.add_parser("status", help="show account quota")
    sp.set_defaults(func=cmd_status)

    tp = sub.add_parser("token", help="print the saved refresh_token (copy to a server)")
    tp.add_argument("-q", "--quiet", action="store_true",
                    help="print only the token (for scripts)")
    tp.set_defaults(func=cmd_token)

    vp = sub.add_parser("servers", help="list available egress countries")
    vp.set_defaults(func=cmd_servers)

    rp = sub.add_parser("run", help="start local SOCKS5 + HTTP proxy")
    rp.add_argument("--country", help="egress country ISO code (overrides config)")
    rp.add_argument("--host")
    rp.add_argument("--http-port", type=int)
    rp.add_argument("--socks-port", type=int)
    rp.add_argument("--failover", type=int,
                    help="number of nodes to try per connection (default 3)")
    rp.set_defaults(func=cmd_run)

    wp = sub.add_parser("web", help="open the local web control panel")
    wp.add_argument("--web-host", default="127.0.0.1")
    wp.add_argument("--web-port", type=int, default=8765)
    wp.add_argument("--no-open", action="store_true", help="don't auto-open a browser")
    wp.set_defaults(func=cmd_web)
    return p


def _prompt(msg, default=""):
    v = input(f"{msg}" + (f" [{default}]" if default else "") + ": ").strip()
    return v or default


def interactive(config_path=None):
    ns = argparse.Namespace(config=config_path)
    while True:
        print("\n=== fxproxy — Firefox IP Protection 落地代理 ===")
        print("  1) 登录/入组 (login)   —— 邮箱密码 或 sessionToken → 换凭证并入组")
        print("  2) 查看配额 (status)")
        print("  3) 列出可用国家 (servers)")
        print("  4) 启动代理 (run)")
        print("  5) 可视化控制面板 (web)")
        print("  6) 显示 refresh_token (拷到服务器用)")
        print("  7) 退出")
        choice = input("选择指令 [1-7]: ").strip()
        try:
            if choice == "1":
                mode = _prompt("凭证方式: 1=邮箱密码  2=sessionToken", "1")
                a = argparse.Namespace(config=config_path, email=None, password=None,
                                       session_token=None, country=None)
                if mode == "2":
                    a.session_token = _prompt("粘贴 sessionToken(hex)")
                else:
                    a.email = _prompt("FxA 邮箱")
                    a.password = getpass.getpass("FxA 密码: ")
                a.country = _prompt("默认出口国家(留空=任意, 如 US/GB/DE)", "") or None
                cmd_login(a)
            elif choice == "2":
                cmd_status(ns)
            elif choice == "3":
                cmd_servers(ns)
            elif choice == "4":
                a = argparse.Namespace(config=config_path, country=None,
                                       host=None, http_port=None, socks_port=None,
                                       failover=None)
                a.country = _prompt("出口国家(留空=用配置/任意)", "") or None
                print("(Ctrl+C 停止)")
                cmd_run(a)
            elif choice == "5":
                a = argparse.Namespace(config=config_path, web_host=None,
                                       web_port=None, no_open=False)
                print("(Ctrl+C 停止)")
                cmd_web(a)
            elif choice == "6":
                cmd_token(ns)
            elif choice in ("7", "q", "quit", "exit"):
                print("bye")
                return 0
            else:
                print("无效选择")
        except SystemExit:
            pass
        except KeyboardInterrupt:
            print("\n(已取消)")
        except Exception as e:
            print(f"[!] 出错: {e}")


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not getattr(args, "cmd", None):
        return interactive(args.config)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
