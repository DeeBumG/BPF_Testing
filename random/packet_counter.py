from bcc import BPF
import time

b = BPF(src_file="packet_counter.c")

fn = b.load_func("packet_watch", BPF.XDP)

device = "ens33"

try:
    b.attach_xdp(device, fn, 0)
    print(f"BPF XDP program attached to {device} successfully!")
except Exception as e:
    print(f"Failed to attach to {device}: {e}")
    exit()

def read_total_counter():
    counter_map = b.get_table("pkt_counter")
    val = counter_map[0][1]
    return val

def read_ICMP_counter():
    counter_map = b.get_table("pkt_counter")
    val = counter_map[1][1]
    return val

try:
    print("Incoming Packet Count Begun")
    while True:
        total_counter = read_total_counter()
        ICMP_counter = read_ICMP_counter()
        print(f"\rPacket Count: {total_counter} ICMP: {ICMP_counter}", end='', flush=True)
        #print(f"\rICMP Count: {ICMP_counter}", end='', flush=True)
        time.sleep(1)

except KeyboardInterrupt:
    print("\nDetaching XDP program...")
    b.remove_xdp(device, 0)
    print("Program detached. Exiting...")
