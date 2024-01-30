#Nazwa projektu: CyBORgi
#Autorzy pliku: Filip Browarny, Krzysztof Kluczyński, Hubert Brzóskniewicz, Kamil Kułak
import socket
import json
import argparse
from threading import Thread
import random
import cbor2
from authenticationManager import AuthenticationManager
import base64
from collections import deque

SERVER_IP = 'localhost'
SERVER_PORT = 9091
DEVICES_NUM = 2
ID_OF_FIRST = 200
HISTORY_LEN = 10
TEST_SCENARIO = 'start_client'


class Recorder:
    def __init__(self, recorder_id, recorder_ip, recorder_port, history_len):
        self.device_id = recorder_id
        self.gateway_address = (recorder_ip, recorder_port)
        self.history = deque(maxlen=history_len)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.authenticationManager = AuthenticationManager()
        self.authenticationManager.generete_key_pair()

    def __del__(self):
        try:
            self.socket.close()
            print("Recorder " + str(self.device_id) + " closed socket successfully.")
        except socket.error as e:
            print(f"Error while closing the socket: {e}")

    def send_register_message(self) -> None:
        public_key_pem = self.authenticationManager.get_public_key_pem()

        register_message = {
            "action": "register",
            "device_id": self.device_id,
            "public_key": public_key_pem,
            "device_type": "recorder"
        }
        register_message = cbor2.dumps(register_message)

        self.socket.sendto(register_message, self.gateway_address)
        print(f'Sent register message from device {self.device_id}')

        while True:

            confirmation = self.socket.recvfrom(1024)[0]

            json_confirmation = json.loads(confirmation)
            json_confirmation['public_key'] = json_confirmation['public_key'].encode('utf-8')
            if json_confirmation["action"] != "register_confirmation" or json_confirmation["device_type"] != "recorder":
                continue
            if json_confirmation["status"]:
                print(f"Registration of {self.device_id} succesfull")
                self.gateway_pub_key_pem = json_confirmation["public_key"]
            else:
                print(f"Registration of {self.device_id} unsuccesfull")
            return

    def send_unregister_message(self) -> None:
        signature = self.authenticationManager.sign_message(self.device_id)

        unregister_message = {
            "action": "unregister",
            "device_id": self.device_id,
            "device_type": "recorder",
            "signature": signature
        }

        unregister_message = cbor2.dumps(unregister_message)

        self.socket.sendto(unregister_message, self.gateway_address)
        print(f'Sent unregister message from device {self.device_id}')

        while True:

            confirmation = self.socket.recvfrom(1024)[0]

            json_confirmation = json.loads(confirmation)
            if json_confirmation["action"] != "unregister_confirmation" or json_confirmation["device_type"] != "recorder":
                continue
            if json_confirmation["status"]:
                print(f"Unregistration of {self.device_id} succesfull")
            else:
                print(f"Unregistration of {self.device_id} unsuccesfull")
            return

    def check_signature(self, data, signature, pub_key):
        return self.authenticationManager.verify_signature(data, signature, pub_key)

    def listen_for_data(self):
        while True:
            data, addr = self.socket.recvfrom(1024)
            if data in self.history:
                print(f"\n\n\nreceived duplicated message, skipping: {data}\n\n\n")
                continue
            self.history.append(data)
            self.process_data(data)

    def process_data(self, data):
        decoded_data = json.loads(data)
        decoded_data['signature'] = base64.b64decode(decoded_data['signature'])
        if (self.check_signature(decoded_data['data'], decoded_data['signature'], self.gateway_pub_key_pem)):
            print(f"Recorder {self.device_id} received data: {decoded_data}")
        else:
            print(f"Received wrongly signed data from gateway")

class RecorderManager:
    def __init__(self, devices_num, server_ip, server_port, id_of_first, history_len, test_scenario):
        self.devices_num = devices_num
        self.server_ip = server_ip
        self.server_port = server_port
        self.id_of_first = id_of_first
        self.history_len = history_len
        self.threads_list = []
        self.test_scenario = test_scenario

    def start_devices_in_threads(self):
        for i in range(self.devices_num):
            thread = Thread(target=self.test_scenario, args=(self.id_of_first + i,
                                                       self.server_ip, self.server_port,
                                                       self.history_len))
            self.threads_list.append(thread)
            thread.start()

        for thread in self.threads_list:
            thread.join()


def start_client(device_id, server_ip, server_port, history_len):
    recorder = Recorder(device_id, server_ip, server_port, history_len)
    recorder.send_register_message()
    recorder.listen_for_data()

def test_unregister(device_id, server_ip, server_port, history_len):
    recorder = Recorder(device_id, server_ip, server_port, history_len)
    recorder.send_register_message()
    recorder.send_unregister_message()

def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--address", default=SERVER_IP,
                        help="ip address of the server")
    parser.add_argument("-p", "--port", default=SERVER_PORT,
                        help="port of the server")
    parser.add_argument("-dn", "--devices_num", default=DEVICES_NUM,
                        help="number of recorders")
    parser.add_argument("-id", "--id_of_first", default=ID_OF_FIRST,
                        help="id of the first recorders")
    parser.add_argument("-hl", "--history_len", default=HISTORY_LEN,
                        help="number of messages in history log of a recorder")
    parser.add_argument("-t", "--test", default=TEST_SCENARIO,
                        help="choosen test scenario")
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    test_function = globals().get(args.test)

    manager = RecorderManager(int(args.devices_num), args.address, int(args.port), int(args.id_of_first), int(args.history_len), test_function)
    manager.start_devices_in_threads()


if __name__ == "__main__":
    main()