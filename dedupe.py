#!/usr/bin/env python3
"""
dedupe.py

Features:
- Accepts filenames via CLI or interactive prompt
- Normalize hostnames and dedupe
- Optional: collapse duplicates by resolved IP (--collapse-by-ip)
- Optional: probe with httpx (--probe) and save live results

Outputs:
    merged_subs.txt (default) - deduped host list
    merged_subs_ip_map.csv (when --collapse-by-ip) - hostname,ip
    merged_subs_live.txt (when --probe) - httpx output
"""

from pathlib import Path
from urllib.parse import urlparse
import re
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import sys
import csv


# ---------------------
# Normalization
# ---------------------
def normalize_entry(line: str) -> str:
    s = line.strip()
    if not s:
        return ""
    s = s.strip("<>\"'")

    # If line looks like a URL with scheme, parse normally; else coerce with http://
    try:
        parsed = urlparse(s if "://" in s else "http://" + s)
    except Exception:
        parsed = urlparse(s)

    host = parsed.hostname or parsed.path
    if not host:
        m = re.search(r"([A-Za-z0-9\-_.]+\.[A-Za-z]{2,})", s)
        host = m.group(1) if m else ""

    host = re.sub(r"^\*\.", "", host)       # remove leading wildcard
    host = host.rstrip(".")
    host = re.sub(r":\d+$", "", host)       # strip trailing port if any
    host = host.lower().strip()
    if not host or "." not in host:
        return ""
    return host


# -----------------------
# Read files
# -----------------------
def read_file_lines(path: Path):
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return [line.rstrip("\n") for line in fh]
    except FileNotFoundError:
        print(f"[!] File not found: {path}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] Error reading {path}: {e}", file=sys.stderr)
        return []


# ---------------------------
# DNS resolution (threaded)
# ---------------------------
def resolve_host(host: str, timeout: float = 3.0):
    orig_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        # socket.gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
        _, _, ips = socket.gethostbyname_ex(host)
        return host, (ips[0] if ips else None)
    except Exception:
        return host, None
    finally:
        socket.setdefaulttimeout(orig_timeout)


def resolve_all(hosts, threads=30, timeout=3.0):
    results = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve_host, h, timeout): h for h in hosts}
        for fut in as_completed(futures):
            h, ip = fut.result()
            results[h] = ip
    return results


# -------------------------
# HTTPX Probe
# -------------------------
def run_httpx(input_path: Path, output_path: Path, extra_args: list = None):
    extra_args = extra_args or ["-silent", "-status-code", "-title"]
    cmd = ["httpx", "-l", str(input_path), "-o", str(output_path)] + extra_args
    try:
        proc = subprocess.run(
            cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if proc.returncode != 0 and proc.stderr:
            # httpx sometimes returns non-zero even when it produced output
            print("[!] httpx warning:", proc.stderr.strip(), file=sys.stderr)
    except FileNotFoundError:
        raise FileNotFoundError("httpx not found in PATH. Install httpx to enable probing.")


# -----------------------
# Main
# -----------------------
def main():
    parser = argparse.ArgumentParser(
        description="Merge, normalize and dedupe subdomain lists. Optional IP collapse and httpx probing."
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Text files containing subdomains (one per line). If omitted you'll be prompted.",
    )
    parser.add_argument(
        "-o", "--output", default="merged_subs.txt", help="Output deduped filename (default merged_subs.txt)"
    )
    parser.add_argument(
        "--collapse-by-ip",
        dest="collapse_by_ip",
        action="store_true",
        help="Resolve hosts and collapse by first-seen IP (also writes *_ip_map.csv and *_collapsed.txt)",
    )
    parser.add_argument(
        "--probe", action="store_true", help="Run httpx on deduped (or collapsed) list and save *_live.txt"
    )
    parser.add_argument("--threads", type=int, default=30, help="Threads for DNS resolution (default 30)")
    parser.add_argument(
        "--dns-timeout", type=float, default=3.0, help="DNS timeout seconds per host (default 3.0)"
    )
    args = parser.parse_args()

    files = [Path(f).expanduser() for f in args.files]
    if not files:
        print("Enter paths to your subdomain files, one per line. Blank line to finish.")
        while True:
            entry = input("file> ").strip()
            if not entry:
                break
            files.append(Path(entry).expanduser())

    if not files:
        print("No files provided. Exiting.")
        return

    total_lines = 0
    raw_lines = []
    for p in files:
        lines = read_file_lines(p)
        total_lines += len(lines)
        raw_lines.extend(lines)

    # Normalize & dedupe
    normalized = [normalize_entry(l) for l in raw_lines]          # <-- l, not 1
    normalized = [n for n in normalized if n]                     # <-- 'in' was missing
    unique_hosts = sorted(set(normalized))

    # Write merged output (pre-collapse)
    out_path = Path(args.output).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(unique_hosts) + ("\n" if unique_hosts else ""))

    print(f"\nSaved deduped host list -> {out_path.resolve()}")
    print(f"Files processed: {len(files)}")
    print(f"Total lines read: {total_lines}")
    print(f"Normalized items: {len(normalized)}")
    print(f"Unique hosts: {len(unique_hosts)}")
    print(f"Duplicates removed: {len(normalized) - len(unique_hosts)}")

    # Optional: collapse by IP
    if args.collapse_by_ip:
        print("\n[*] Resolving hosts (this may take a moment)...")
        resolutions = resolve_all(unique_hosts, threads=args.threads, timeout=args.dns_timeout)

        # ip -> first-seen host mapping
        ip_to_host = {}
        host_ip_map = {}
        for h in unique_hosts:
            ip = resolutions.get(h)                                # <-- resolutions, not resolution
            host_ip_map[h] = ip or ""
            if ip and ip not in ip_to_host:
                ip_to_host[ip] = h

        # Write ip_map.csv: host, ip
        ip_map_path = out_path.with_name(out_path.stem + "_ip_map.csv")
        with ip_map_path.open("w", newline="", encoding="utf-8") as csvf:
            writer = csv.writer(csvf)
            writer.writerow(["hostname", "ip"])
            for h, ip in host_ip_map.items():                      # <-- items(), not item()
                writer.writerow([h, ip])
        print(f"Saved hostname -> IP map -> {ip_map_path.resolve()}")

        # Build collapsed list (unique host per IP + unresolved)
        collapsed = []
        seen_ips = set()
        for h in unique_hosts:
            ip = host_ip_map.get(h)
            if not ip:
                collapsed.append(h)  # keep unresolved
                continue
            if ip not in seen_ips:
                seen_ips.add(ip)
                collapsed.append(ip_to_host[ip])  # canonical host for this IP

        collapsed_path = out_path.with_name(out_path.stem + "_collapsed.txt")
        collapsed_path.write_text("\n".join(collapsed) + ("\n" if collapsed else ""))
        print(f"Saved collapsed-by-IP list -> {collapsed_path.resolve()}")
        print(f"Total collapsed list size: {len(collapsed)} (unique IPs + unresolved hosts)")

    # Optional: probe with httpx
    if args.probe:
        try:
            probe_input = out_path
            # if collapse-by-ip used, prefer collapsed list if it exists
            collapsed_candidate = out_path.with_name(out_path.stem + "_collapsed.txt")
            if args.collapse_by_ip and collapsed_candidate.exists():
                probe_input = collapsed_candidate
            live_out = out_path.with_name(out_path.stem + "_live.txt")
            print(f"\n[*] Running httpx on {probe_input} -> {live_out}")
            run_httpx(probe_input, live_out)
            print(f"Saved httpx results -> {live_out.resolve()}")
        except FileNotFoundError as e:
            print(f"[!] {e}", file=sys.stderr)
            print("[!] Install httpx (https://github.com/projectdiscovery/httpx) and ensure it's in PATH to enable probing.", file=sys.stderr)


if __name__ == "__main__":
    main()
