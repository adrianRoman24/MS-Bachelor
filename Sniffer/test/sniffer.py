from scapy.all import *
from "../bloomfilter.py" import BloomFilter
import datetime
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from threading import Timer, Thread, Lock
import requests
from copy import deepcopy

###Raspberry Pi 3 Model B+

# config
config = None

# epoch variables
epoch_bloom_filter = None
epoch_start_timestamp = None
epoch_end_timestamp = None
current_pkcs = None
to_register_clients_pkcs = None
to_unregister_clients_pkcs = None
lock = Lock()

def log(string):
    print(str(datetime.datetime.now()) + ': ' + string)

def init_config():
    global config
    file = open("./config.json")
    config = json.load(file)
    file.close()

def init_sync():
    global config, epoch_bloom_filter, current_pkcs, to_register_clients_pkcs, to_unregister_clients_pkcs
    epoch_bloom_filter = BloomFilter(config["BLOOM_FILTER_MAX_SIZE"], config["BLOOM_FILTER_FALSE_POS_PROBABILITY"])
    current_pkcs = set()
    to_register_clients_pkcs = set()
    to_unregister_clients_pkcs = set()

def packet_handler(frame):
    global epoch_bloom_filter, lock
    # handle only dot11 probe requests
    if frame.haslayer(Dot11ProbeReq):
        source = frame[Dot11].addr2
        if not epoch_bloom_filter.check(source):
            log("[DETECTION] Source: " + source)
            # add source to bloom filter
            lock.acquire()
            epoch_bloom_filter.add(source)
            lock.release()

class httpHandler(BaseHTTPRequestHandler):
    def handle_request(self, response_message, response_code):
        log("[LOG] Request response:" + str(response_message))
        self.send_response(response_code)
        self.end_headers()
        self.wfile.write(json.dumps(response_message, indent = 4).encode())


    def do_POST(self):
        # parse request data
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        req_json = post_data.decode('utf8').replace("'", '"')
        req_data = json.loads(req_json)

        # handle request
        if self.path == config["PKC_REGISTER_PATH"]:
            # register user starting with next epoch
            if 'pkc' not in req_data or "serializedPkc" not in req_data:
                self.handle_request({
                    "error": {
                        "message": "Public key (pkc or serializedPkc) of consumer not found"
                    }
                }, 400)
            else:
                global to_register_clients_pkcs
                to_register_clients_pkcs.add((req_data["pkc"], req_data["serializedPkc"]))
                self.handle_request(dict({
                    "result": {
                        "message": "Public key (pkc) of consumer added to be registered"
                    }
                }), 200)
        elif self.path == config["PKC_UNREGISTER_PATH"]:
            # unregister user starting with next epoch
            if 'pkc' not in req_data or "serializedPkc" not in req_data:
                self.handle_request({
                    "error": {
                        "message": "Public key (pkc) of consumer not found"
                    }
                }, 400)
            else:
                global to_unregister_clients_pkcs
                to_unregister_clients_pkcs.add((req_data["pkc"], req_data["serializedPkc"]))
                self.handle_request({
                    "result": {
                        "message": "Public key (pkc) of consumer added to be unregistered"
                    }
                }, 200)
        else:
            self.handle_request({
                "error": {
                    "message": "Unknown path"
                }
            }, 400)


def listening_thread_target():
    global config
    server = HTTPServer((config["HOST"], config["PORT"]), httpHandler)
    log("[LOG] Server running on PORT " + str(config["PORT"]))
    server.serve_forever()

def sniffing_thread_target():
    global config
    log("[LOG] Start sniffing on interface <" + config["INTERFACE"] + ">")
    sniff(iface = config["INTERFACE"], prn = packet_handler)


def set_interval(function, args, duration):
    function()
    Timer(duration, set_interval, [function, args, duration]).start()


def handle_bloom_filters():
    global epoch_bloom_filter, epoch_start_timestamp, epoch_end_timestamp
    global current_pkcs, to_register_clients_pkcs, to_unregister_clients_pkcs
    global lock

    lock.acquire()

    # collect results for current epoch
    epoch_bloom_filter_copy = deepcopy(epoch_bloom_filter)
    epoch_start_timestamp_copy = deepcopy(epoch_start_timestamp)
    epoch_end_timestamp_copy = deepcopy(epoch_end_timestamp)
    to_register_clients_pkcs_copy = deepcopy(to_register_clients_pkcs)
    to_unregister_clients_pkcs_copy = deepcopy(to_unregister_clients_pkcs)
    current_pkcs_copy = deepcopy(current_pkcs)

    # reset variables for next epoch
    epoch_bloom_filter = BloomFilter(config["BLOOM_FILTER_MAX_SIZE"], config["BLOOM_FILTER_FALSE_POS_PROBABILITY"])
    epoch_start_timestamp = calendar.timegm(time.gmtime())
    epoch_end_timestamp = epoch_start_timestamp + config["EPOCH_INTERVAL_IN_SEC"]
    to_register_clients_pkcs = set()
    to_unregister_clients_pkcs = set()

    lock.release()

    # delete public keys of unregistered consumers
    for to_unregister_client_pkc in to_unregister_clients_pkcs_copy:
        current_pkcs.remove(to_unregister_client_pkc)

    # add public keys of newly registered consumers
    for to_register_clients_pkc in to_register_clients_pkcs_copy:
        current_pkcs.add(to_register_clients_pkc)

    # build epoch result to send to server
    epoch_result = {
        "epoch_start_timestamp": epoch_start_timestamp_copy,
        "epoch_end_timestamp": epoch_end_timestamp_copy,
        "sensor_id": config["SENSOR_ID"],
        "encrypted_bloom_filters": dict()
    }
    log(f"Current bloom filter sum of ones: {sum(epoch_bloom_filter_copy.array)}")
    for pkc, serializedPkc in current_pkcs_copy:
        # make copy of bloom filter array
        bloom_filter_array = deepcopy(epoch_bloom_filter_copy.array)

        # encrypt bloom filter array
        encrypt_request_body = {
            "publicKey": serializedPkc,
            "bloomFilter": bloom_filter_array
        }
        response = requests.post(url = config["ENCRYPT_SERVICE_URL"], json = encrypt_request_body)
        data = response.json()

        # add array to epoch result
        epoch_result["encrypted_bloom_filters"][pkc] = data["result"]
    # send epoch result to server
    log("[LOG] Send epoch result for pkcs: " + str([pkc for pkc, _ in current_pkcs_copy]))
    log("[LOG] epoch_start_timestamp: " + str(epoch_start_timestamp_copy))
    log("[LOG] epoch_end_timestamp: " + str(epoch_end_timestamp_copy))
    requests.post(url = config["SERVER_URL"], json = epoch_result)

def epochs_thread_target():
    set_interval(handle_bloom_filters, [], config["EPOCH_INTERVAL_IN_SEC"])
    
if __name__ == '__main__':
    log("[LOG] Init config")
    init_config()
    log("[LOG] Init sync")
    init_sync()

    # thread used for sniffing
    sniffing_thread = Thread(target = sniffing_thread_target, args = ())
    # thread used for http communication with the server
    listening_thread = Thread(target = listening_thread_target, args = ())
    # thread used for delivering epochs' bloomfilters result
    epochs_thread = Thread(target = epochs_thread_target, args = ())

    # start threads
    sniffing_thread.start()
    listening_thread.start()
    epochs_thread.start()

    # join threads
    sniffing_thread.join()
    listening_thread.join()
    epochs_thread.join()
