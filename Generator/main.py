from scapy.all import *
import csv
from time import sleep

INPUT_FILE = 'sample_input.csv'
DEST_MAC_ADDRESS = 'ff:ff:ff:ff:ff:ff'
SRC_MAC_ADDRESS = '14:4f:8a:ca:55:df'
SSID = 'Sc45y + W1F1'
CHANNEL = chr(11)
INTERFACE = 'wlo1'
# probe request subtype
SUBTYPE = 4
PROBE_REQUEST_INTERVAL = 2.5
SENSOR_ID_KEY = 'SensorCode'
ADDRESS_KEY = 'Address'

def get_detections(filename):
    result = []
    with open(filename, mode='r') as infile:
        reader = list(csv.reader(infile))
        keys = reader[0]
        print(keys)
        for row in reader[1:]:
            elem = dict()
            for i in range(len(keys)):
                elem[keys[i]] = row[i]
            result.append(elem)
    return result

def char_to_mac_char(char):
    if char >= '0' and char <= '9':
        return char
    if char >= 'a' and char <= 'f':
        return char
    int_value = ord(char) % 16
    if int_value < 10:
        return str(int_value)
    int_value -= 10
    return chr(ord('a') + int_value)

def hash_to_mac(hash_arg):
    mac = 'dd'
    for i in range(5):
        mac += ':' + char_to_mac_char(hash_arg[i * 2]) + char_to_mac_char(hash_arg[i * 2 + 1])
    return mac

def send_probe_request(sensor_id, mac_address):
    frame = RadioTap()\
        /Dot11(type = 0, subtype = SUBTYPE, addr1 = DEST_MAC_ADDRESS, addr2 = mac_address, addr3 = DEST_MAC_ADDRESS)\
        /Dot11ProbeReq()\
        /Dot11Elt(ID ='SSID', info=SSID)\
        /Dot11Elt(ID ='Rates', info='\x82\x84\x8b\x96\x0c\x12\x18')\
        /Dot11Elt(ID ='ESRates', info='\x30\x48\x60\x6c')\
        /Dot11Elt(ID ='DSset', info=CHANNEL)
    answer = sendp(frame, iface = INTERFACE)
    #answer,show()

if __name__ == '__main__':
    print('Starting to send probe requests')
    detections = get_detections(INPUT_FILE)
    for detection in detections:
        sensor_id = detection[SENSOR_ID_KEY]
        mac_address = hash_to_mac(detection[ADDRESS_KEY])
        send_probe_request(sensor_id, mac_address)
        sleep(PROBE_REQUEST_INTERVAL)
