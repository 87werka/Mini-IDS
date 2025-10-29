# prosty IDS (nasłuch, alerty, log)
from scapy.all import sniff, IP, TCP
from collections import defaultdict, deque
import time
import logging
import signal
import sys

# mniejsze okno i alert dla łatwiejszego testu
WINDOW = 5 
TRESH = 5
hits = defaultdict(deque) # czas nadejścia pakietó
logging.basicConfig(filename="miniids.log",level=logging.INFO, format="%(asctime)s %(message)s")

def analyze(pkt):
    # dla pakietów ICP/TCP
    now = time.time()
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src = pkt[IP].src
        q = hits[src]
        q.append(now)
    
    # stare wpisy po za oknem czasowym
    while q and now - q[0] > WINDOW:
        q.popleft()

    # alert
    if len(q) >= TRESH:
        msg=f"ATTENTION: SUS ACTIVITY from {src} ({len(q)} pakietów/{WINDOW}s)"
        print(msg)
        logging.info(msg)

def stop_and_report(signum=None, frame= None):
    print("IDS was stopped. Save top Ip to top_ips.txt")
    # wygeneruj ilośc pakietów w osatnim oknie
    counts = [(ip, len(q)) for ip, q in hits.items()]
    counts.sort(key=lambda x: x[1], reverse = True)
    with  open("top_ips.txt","w") as f:
        for ip, c in counts[:20]:
            f.write(f"{ip},{c}\n")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, stop_and_report)
    print("START mini IDS (TCP), Log: ids.log")
    # do nasluchiwania tylko tcp
    sniff(filter = "tcp", prn=analyze, store=0, iface="Wi-Fi")

