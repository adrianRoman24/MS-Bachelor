from cgi import test
from scapy.all import *
from bloomfilter import BloomFilter
from math import log, ceil

IFACE_NAME = "wlx5ca6e630bd88"
bloom_filter = BloomFilter(1000, 0.01)
my_set = set()
kv = dict()


def packet_handler(frame):
    # handle only dot11 probe requests
    if frame.haslayer(Dot11ProbeReq):
        source = frame[Dot11].addr2
        if source[:2] == "cc":
            if len(my_set) % 100 == 0 and source not in my_set:
                real_size = len(my_set)
                estimated_size = ceil(-bloom_filter.size/bloom_filter.hash_count * log(1 - sum(bloom_filter.array) / bloom_filter.size))
                print("Real size: ", real_size)
                print("Estimated size: ", estimated_size)
                kv[real_size] = estimated_size
                print(kv.keys())
                print(kv.values())
            bloom_filter.add(source)
            my_set.add(source)

sniff(iface=IFACE_NAME, prn=packet_handler)
