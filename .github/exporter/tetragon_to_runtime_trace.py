#!/usr/bin/env python3
"""Export Tetragon JSONL events into an in-toto Runtime Trace predicate body."""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_events(path: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def process_from_event(ev: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("process_exec", "process_exit", "process_kprobe"):
        body = ev.get(key)
        if not body:
            continue
        proc = body.get("process") or {}
        binary = proc.get("binary") or proc.get("path")
        if not binary:
            return None
        args = proc.get("arguments")
        if isinstance(args, str):
            arg_list = [args]
        elif isinstance(args, list):
            arg_list = args
        else:
            arg_list = []
        return {
            "eventType": "exit" if key == "process_exit" else "process",
            "processBinary": binary,
            "arguments": arg_list,
        }
    return None


def network_from_event(ev: dict[str, Any]) -> dict[str, Any] | None:
    body = ev.get("process_kprobe") or {}
    sock = None
    for arg in body.get("args") or []:
        if isinstance(arg, dict) and "sock_arg" in arg:
            sock = arg["sock_arg"]
            break
    if not sock:
        return None
    daddr = sock.get("daddr") or sock.get("destination_address")
    dport = sock.get("dport") or sock.get("destination_port")
    if not daddr:
        return None
    dest = f"{daddr}:{dport}" if dport is not None else str(daddr)
    proc = body.get("process") or {}
    return {
        "destination": dest,
        "processBinary": proc.get("binary") or proc.get("path"),
    }


def file_from_event(ev: dict[str, Any]) -> dict[str, Any] | None:
    body = ev.get("process_kprobe") or {}
    for arg in body.get("args") or []:
        if not isinstance(arg, dict):
            continue
        file_arg = arg.get("file_arg") or arg.get("file")
        if isinstance(file_arg, dict):
            path = file_arg.get("path") or file_arg.get("name")
            if path:
                return {"name": path}
        path = arg.get("path") or arg.get("file_path")
        if isinstance(path, str) and path.startswith(("/", ".")):
            return {"name": path}
    return None


def interesting(p: dict[str, Any]) -> bool:
    b = (p.get("processBinary") or "").lower()
    joined = " ".join(str(a) for a in (p.get("arguments") or [])).lower()
    keys = (
        "go",
        "gcc",
        "wget",
        "curl",
        "docker",
        "buildah",
        "buildkit",
        "runc",
        "apk",
        "curl-exfil",
        "blog.saintmalik.me",
        "proxy.golang",
        "github.com",
        "proto-gen-connect",
        "protoc-gen",
        "/tmp/",
        "install ",
    )
    return any(k in b or k in joined for k in keys)


def process_from_kprobe(ev: dict[str, Any]) -> dict[str, Any] | None:
    """Lift process identity from kprobe/LSM events when process_exec is sparse."""
    body = ev.get("process_kprobe") or ev.get("process_lsm") or {}
    proc = body.get("process") or {}
    binary = proc.get("binary") or proc.get("path")
    if not binary:
        return None
    args = proc.get("arguments")
    if isinstance(args, str):
        arg_list = [args]
    elif isinstance(args, list):
        arg_list = args
    else:
        arg_list = []
    return {
        "eventType": "process",
        "processBinary": binary,
        "arguments": arg_list,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--event-name", default="docker-build")
    ap.add_argument("--started", default="")
    ap.add_argument("--finished", default="")
    args = ap.parse_args()

    events = load_events(args.events)
    processes: list[dict[str, Any]] = []
    networks: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []

    for ev in events:
        p = process_from_event(ev)
        if p and interesting(p):
            processes.append(p)
        pk = process_from_kprobe(ev)
        if pk and interesting(pk):
            processes.append(pk)
        n = network_from_event(ev)
        if n:
            networks.append(n)
        f = file_from_event(ev)
        if f:
            files.append(f)

    host_re = re.compile(r"https?://([^/\s\"']+)", re.I)
    for p in processes:
        for arg in p.get("arguments") or []:
            for host in host_re.findall(str(arg)):
                host = host.strip().rstrip(")")
                if ":" not in host:
                    host = f"{host}:443"
                networks.append(
                    {
                        "destination": host,
                        "processBinary": p.get("processBinary"),
                    }
                )

    def dedupe(items: list[dict[str, Any]], key_fn):
        seen = set()
        out = []
        for it in items:
            k = key_fn(it)
            if k in seen:
                continue
            seen.add(k)
            out.append(it)
        return out

    processes = dedupe(
        processes, lambda x: (x.get("processBinary"), tuple(x.get("arguments") or []))
    )
    networks = dedupe(
        networks, lambda x: (x.get("destination"), x.get("processBinary"))
    )
    files = dedupe(files, lambda x: x.get("name"))

    if not processes and not networks and not files:
        print(f"empty Trace from {len(events)} raw events", file=sys.stderr)
        return 2

    predicate = {
        "monitor": {
            "type": "https://github.com/cilium/tetragon/v1.7.0",
            "tracePolicy": {
                "policies": [
                    {
                        "Name": "process-lifecycle",
                        "Config": "tetragon-default (exec/exit without TracingPolicy)",
                    },
                    {
                        "Name": "connect",
                        "Config": ".github/tetragon-policies/connect.yaml",
                    },
                    {
                        "Name": "file-access",
                        "Config": ".github/tetragon-policies/file-access.yaml",
                    },
                ]
            },
        },
        "monitoredProcess": {
            "hostID": "https://github.com/actions",
            "type": "https://github.com/actions/runner",
            "event": args.event_name,
        },
        "monitorLog": {
            "process": processes,
            "network": networks,
            "fileAccess": files,
        },
        "metadata": {
            "buildStartedOn": args.started or utc_now(),
            "buildFinishedOn": args.finished or utc_now(),
            "rawEventCount": len(events),
            "exporter": ".github/exporter/tetragon_to_runtime_trace.py",
        },
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(predicate, f, indent=2)
        f.write("\n")
    print(
        json.dumps(
            {
                "rawEvents": len(events),
                "process": len(processes),
                "network": len(networks),
                "fileAccess": len(files),
                "out": args.out,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
