#!/usr/bin/env python3
"""从 results/*/negative-save.json 生成六列对照表（tag / 大小 / 报成功 / 文件数 / ack / 终态）。
ack delta 从同目录 summary 里抓；终态取 json 的 transfer_state_after（未捕获则写「未取到」）。"""
import glob, json, os, re, sys
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rows = []
for d in sorted(glob.glob(os.path.join(root, "results", "*"))):
    tag = os.path.basename(d)
    j = os.path.join(d, "negative-save.json")
    if not os.path.exists(j):
        continue
    data = json.load(open(j))
    vs = data.get("verdicts", [])
    ui = ",".join(str(v.get("ui_says_saved")) for v in vs)
    files = ",".join(str(len(v.get("files") or [])) for v in vs)
    states = [v.get("transfer_state_after") for v in vs]
    state = "/".join(str(s) if s else "未取到" for s in states)
    szf = os.path.join(d, f"negative-save-size-{tag}.txt")
    if os.path.exists(szf):
        sz = int(open(szf).read().strip())
    else:
        sz = 16777216  # 那几轮固定 16 MiB
    summary = os.path.join(d, f"negative-save-summary-{tag}.txt")
    ack = "未记录"
    if os.path.exists(summary):
        m = re.search(r"ack 计数\s*:\s*前 (\d+) → 后 (\d+)（delta=(\d+)）", open(summary).read())
        if m:
            ack = f"{m.group(1)} → {m.group(2)}（delta={m.group(3)}）"
    rows.append((tag, sz, ui, files, ack, state))

def human(n):
    return f"{n} B" if n < 1024 else (f"{n/1024:.0f} KiB" if n < 1048576 else f"{n/1048576:.0f} MiB")

print("| 镜像 tag | 文件大小 | 界面「已保存至本机」 | downloads 文件数 | ack 计数 | 传输最终状态 |")
print("|---|---|---|---|---|---|")
for tag, sz, ui, files, ack, state in rows:
    print(f"| {tag} | {human(sz)} | {ui} | {files} | {ack} | {state} |")
if not rows:
    print("| （无数据） | | | | | |")
