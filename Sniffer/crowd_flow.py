from cgi import test
from scapy.all import *
from bloomfilter import BloomFilter
from math import log, ceil

IFACE_NAME = "wlx5ca6e630bd88"
n = 850
p = 0.01
max_crowd_flow = 100
step = 5

bloom_filter1 = BloomFilter(n, p)
bloom_filter2 = BloomFilter(n, p)
my_set1 = set()
my_set2 = set()
kv = dict()

def intersection():
    bloom_filter_result = []
    for i in range(len(bloom_filter1.array)):
        bloom_filter_result.append(bloom_filter1.array[i] * bloom_filter2.array[i])
    real = len(my_set1.intersection(my_set2))
    m = len(bloom_filter_result)
    t = sum(bloom_filter_result)
    t1 = sum(bloom_filter1.array)
    t2 = sum(bloom_filter2.array)
    k = bloom_filter1.hash_count
    c1 = ceil(- m / k * log(1 -  t/ m))
    c2 = ceil((log(m - (t * m - t1 * t2) / (m - t1 - t2 + t)) - log(m)) / (k * log(1 - 1 / m)))
    return (real, c1, c2)

def number_to_char_16(number):
    mod = number % 16
    if mod  < 10:
        return str(number)
    if mod  == 10:
        return "a"
    if mod == 11:
        return "b"
    if mod == 12:
        return "c"
    if mod == 13:
        return "d"
    if mod == 14:
        return "e"
    return "f"

def generate():
    mac_adddresses = []
    count = 0
    for i in range(16):
        if (count > 2*n):
            break
        a = number_to_char_16(i)
        for j in range(16):
            if (count > 2*n):
                break
            b = number_to_char_16(j)
            for k in range(16):
                if (count > 2*n):
                    break
                c = number_to_char_16(k)
                for m in range(16):
                    count += 1
                    d = number_to_char_16(m)
                    mac_address = "cc" + ":" + "00:00:00:" + a + b + ":" + c + d
                    mac_adddresses.append(mac_address)
                    if (count > 2*n):
                        break
    return mac_adddresses

if __name__ == '__main__':
    print('start')
    x = []
    y1 = []
    y2 = []
    mac_addresses = generate()
    for crowd_flow in range(0, max_crowd_flow + 1, step):
        bloom_filter1 = BloomFilter(n, p)
        bloom_filter2 = BloomFilter(n, p)
        my_set1 = set()
        my_set2 = set()
        first = mac_addresses[:max_crowd_flow - crowd_flow]
        second = mac_addresses[max_crowd_flow - crowd_flow:2 * max_crowd_flow - 2 * crowd_flow]
        third = mac_addresses[2 * max_crowd_flow - 2 * crowd_flow: 2 * max_crowd_flow - crowd_flow]
        for mac in first:
            bloom_filter1.add(mac)
            my_set1.add(mac)
        for mac in second:
            bloom_filter2.add(mac)
            my_set2.add(mac)
        for mac in third:
            bloom_filter1.add(mac)
            my_set1.add(mac)
            bloom_filter2.add(mac)
            my_set2.add(mac)
        real, c1, c2 = intersection()
        x.append(real)
        y1.append(c1)
        y2.append(abs(c2))
    print(x)
    print(y2)
            


    
