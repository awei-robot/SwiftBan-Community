#!/usr/bin/env python3
"""测试专用防火墙替身：仅写 FAKE_FW_DIR，绝不调用真实防火墙。"""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["FAKE_FW_DIR"])
root.mkdir(parents=True, exist_ok=True)
family = "v6" if Path(sys.argv[0]).name == "ip6tables" else "v4"
args = sys.argv[1:]
with (root / "lock").open("a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    state = root / f"{family}.json"
    rules = json.loads(state.read_text()) if state.exists() else []
    with (root / "calls.jsonl").open("a") as out:
        out.write(json.dumps([family, *args]) + "\n")
    action = args[0]
    if action == "-L":
        raise SystemExit(0)
    if action == "-S":
        if (root / f"fail-query-{family}").exists():
            print("mock query failure", file=sys.stderr)
            raise SystemExit(2)
        print("-P INPUT ACCEPT")
        print("-N DOCKER-USER")
        for rule in rules:
            if len(args) > 1 and args[1] != rule["chain"]:
                continue
            text = f'-A {rule["chain"]} -s {rule["ip"]}'
            if rule["comment"]:
                text += f' -m comment --comment {rule["comment"]}'
            print(text + " -j DROP")
        raise SystemExit(0)
    chain = args[1]
    address = str(ipaddress.ip_network(args[args.index("-s") + 1], strict=False))
    comment = args[args.index("--comment") + 1] if "--comment" in args else ""
    rule = {"chain": chain, "ip": address, "comment": comment}
    if action == "-C":
        if rule in rules:
            raise SystemExit(0)
        print("Bad rule (does a matching rule exist in that chain?).", file=sys.stderr)
        raise SystemExit(1)
    if action == "-I":
        fail = root / "fail-insert"
        if fail.exists() and fail.read_text().strip() in ("*", address.split("/")[0]):
            print("mock insert failure", file=sys.stderr)
            raise SystemExit(2)
        rules.insert(0, rule)
    elif action == "-D":
        if (root / "fail-delete").exists():
            print("mock delete failure", file=sys.stderr)
            raise SystemExit(2)
        if rule not in rules:
            raise SystemExit(1)
        rules.remove(rule)
    else:
        raise SystemExit(2)
    state.write_text(json.dumps(rules))
