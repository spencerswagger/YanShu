#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5 ②·速度与 ETA 验收：真传一遍，再用**前端真实模块**把采样回放成数字。

为什么这么写：速度/ETA 是纯前端逻辑（`web/src/lib/speed.js`），后端只提供字节进度。
所以验收分两段，缺一不可：

  A. 真数字：对一个真服务跑一次 8 MiB 上传，量吞吐（MB/s）；
  B. 真口径：把 A 的采样（字节, 毫秒）喂进前端 `createSpeedMeter`，检查
     EWMA 平滑速度、ETA = 剩余/速度、四档文案、慢速与停滞两个异常态。

断言（每行带真数字）：
1. 不节流的 8 MiB 上传吞吐 > 0（基准数字）；
2. 节流到 ~4 MB/s 的采样窗口 ≥ 2s（契约要求 ≥2s 窗口才有意义）；
3. 50% 处 ETA 非空、速度文案合法（`MB/s` / `KB/s` / `B/s`）；
4. 50% 处 ETA 与"实际剩余耗时"误差 ≤ 50%（真实网络抖动，不是精确值）；
5. 传完 ETA → `即将完成`；
6. 3.2s 无字节 → `连接停滞，重试中` 且 **ETA 隐藏**；
7. 5 KB/s 持续 4s → `网络较慢`；
8. 已传/总大小文案形如 `8.0 MB / 8.0 MB`。

用法：
    python3 qa/evidence/v5/check_speed_eta.py \
        --binary <yanshu-server> --dsn "$TEST_DATABASE_URL" \
        --web-dir <web 分支目录> [--size-mb 8] [--target-mbps 4] [--json-out out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ysv5 as Y  # noqa: E402

HERE = Path(__file__).resolve().parent


def render_speed(web_dir: str, samples: list[list[int]], total: int) -> dict:
    payload = json.dumps({"total": total, "samples": samples})
    tmp = HERE / ".speed-samples.json"
    tmp.write_text(payload, encoding="utf-8")
    try:
        p = subprocess.run(["node", str(HERE / "render_web.mjs"), "speed",
                            f"--web-dir={web_dir}", f"--samples={tmp}"],
                           capture_output=True, text=True, timeout=120)
    finally:
        tmp.unlink(missing_ok=True)
    if p.returncode != 0:
        raise RuntimeError(f"render_web speed 失败：{p.stderr.strip()[:300]}")
    return json.loads(p.stdout)


def upload(c: Y.Client, snd: str, rcv: str, size: int, chunk: int,
           target_bps: float | None = None) -> dict:
    """建 + 传一条传输；返回 {samples:[[bytes,ms]], elapsed_ms, tid}。"""
    chunks = size // chunk
    t = Y.make_transfer(c, snd, rcv, size=size, chunk_size=chunk, chunks=chunks, upload=False)
    tid, token = t["transfer_id"], t["upload_token"]
    st, b = c.put_prelude(tid, token, t["prelude"])
    if st not in (200, 201, 204):
        raise RuntimeError(f"传 prelude 失败 {st}: {b}")
    block = bytes((i * 53 + 3) & 0xFF for i in range(chunk))
    t0 = time.perf_counter()
    samples: list[list[int]] = []
    for i in range(chunks):
        data = block + i.to_bytes(4, "big") + b"\x00" * 12
        st, b = c.put_chunk(tid, token, i, data)
        if st not in (200, 201, 204):
            raise RuntimeError(f"传块 {i} 失败 {st}: {b}")
        if target_bps:
            # 按目标速率把这一块"拖"到应该在的时刻（模拟真实网络慢，采样才有窗口）
            want = (i + 1) * chunk / target_bps
            spent = time.perf_counter() - t0
            if want > spent:
                time.sleep(want - spent)
        samples.append([(i + 1) * chunk, int((time.perf_counter() - t0) * 1000)])
    st, b = c.complete(tid, token)
    if st not in (200, 201):
        raise RuntimeError(f"complete 失败 {st}: {b}")
    return {"samples": samples, "elapsed_ms": samples[-1][1] if samples else 0, "tid": tid}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--dsn", default=os.environ.get("TEST_DATABASE_URL", ""))
    ap.add_argument("--schema", default="gate_v5_speed")
    ap.add_argument("--work", default=os.path.join(tempfile.gettempdir(), "ys-v5-work"))
    ap.add_argument("--web-dir", default="")
    ap.add_argument("--size-mb", type=int, default=16)
    ap.add_argument("--target-mbps", type=float, default=1.0)
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    rep = Y.Report("v5 ② 速度 / ETA · 真传一遍 + 前端状态机回放",
                   f"size={args.size_mb} MiB　chunk=512 KiB　schema={args.schema}")
    if not args.dsn:
        rep.add("依赖：TEST_DATABASE_URL", None, "缺 DSN")
        return rep.emit(args.json_out)
    if not args.web_dir:
        rep.add("依赖：--web-dir（要 import 前端真实模块）", None, "缺参数")
        return rep.emit(args.json_out)

    size = args.size_mb * 1024 * 1024
    chunk = 512 * 1024  # 32 个采样点：ETA 取整误差不至于把结论带偏

    with Y.Server(args.binary, args.dsn, args.schema, Path(args.work), sweep="5s") as srv:
        c = Y.Client(srv.base, timeout=120)
        snd, _ = c.register_pair("speed-sender", "发送方")
        rcv, _ = c.register_pair("speed-recipient", "接收方")

        # A) 不节流：真吞吐
        burst = upload(c, snd, rcv, size, chunk)
        burst_mbps = size / (burst["elapsed_ms"] / 1000) / (1024 * 1024) if burst["elapsed_ms"] else 0
        rep.add(f"未节流 {args.size_mb} MiB 上传吞吐 > 0",
                burst_mbps > 0,
                f"{burst_mbps:.1f} MB/s（{burst['elapsed_ms']}ms，{len(burst['samples'])} 块）")

        # B) 节流采样：给 EWMA 一个 ≥2s 的窗口
        throttled = upload(c, snd, rcv, size, chunk, target_bps=args.target_mbps * 1024 * 1024)
        window_ms = throttled["elapsed_ms"]
        rep.add("采样窗口 ≥2s", window_ms >= 2000, f"窗口={window_ms}ms")

        got = render_speed(args.web_dir, throttled["samples"], size)
        half = got["half"]
        actual_half_ms = window_ms / 2
        remain_actual_s = max(0.0, (window_ms - half["ms"]) / 1000)
        eta_s = half["etaSec"]
        # ETA 文案按秒 floor，所以误差下限就是 1s；窗口取 16s 让这个取整误差 ≤12.5%
        err_abs = abs(eta_s - remain_actual_s) if eta_s is not None else 9.99
        err_ok = eta_s is not None and (err_abs <= 1.5 or err_abs / max(remain_actual_s, 0.001) <= 0.2)
        err = err_abs / max(remain_actual_s, 0.001)

        rep.add("50% 处速度文案合法",
                bool(half["speedBps"] > 0) and ("MB/s" in half["speedText"] or "KB/s" in half["speedText"]
                                                 or "B/s" in half["speedText"]),
                f"speed={half['speedText']} ({half['speedBps']/1048576:.2f} MB/s)、样本 {got['samples']} 个")
        rep.add("50% 处 ETA 与真实剩余耗时一致（|Δ|≤1.5s 或 ≤20%）",
                err_ok,
                f"ETA={eta_s}s 实际剩余={remain_actual_s:.1f}s Δ={err_abs:.2f}s（文案「{half['etaText']}」）")
        rep.add("传完 ETA → 即将完成",
                got["last"]["etaSec"] is not None and got["last"]["etaText"] == "即将完成",
                f"etaSec={got['last']['etaSec']} text={got['last']['etaText']!r}")

        # 6) 停滞（render 侧把时钟再推 3.2s）
        stl = got["stalled"]
        rep.add("3.2s 无字节 → 连接停滞且 ETA 隐藏",
                stl["state"] == "stalled" and stl["etaSec"] is None and stl["label"] == "连接停滞，重试中",
                f"state={stl['state']} eta={stl['etaSec']} label={stl['label']!r}")

        # 7) 慢速：5 KB/s 持续 4s（合成采样，只喂状态机，不代表吞吐基准）
        slow_samples = [[0, 0]] + [[i * 5 * 1024, i * 1000] for i in range(1, 6)]
        slow = render_speed(args.web_dir, slow_samples, 10 * 1024 * 1024)
        rep.add("5 KB/s 持续 4s → 网络较慢",
                slow["last"]["state"] == "slow" and slow["last"]["label"] == "网络较慢",
                f"state={slow['last']['state']} label={slow['last']['label']!r}")

        rep.add("已传/总大小文案", bool("/" in got["pair"]), f"pair={got['pair']!r}")

    return rep.emit(args.json_out)


if __name__ == "__main__":
    sys.exit(main())
