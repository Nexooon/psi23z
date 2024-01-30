#Nazwa projektu: CyBORgi
#Autorzy pliku: Filip Browarny, Krzysztof Kluczyński, Hubert Brzóskniewicz, Kamil Kułak
import socket
import cbor2
import argparse
from threading import Thread
import random
import time
from authenticationManager import AuthenticationManager

SERVER_IP = 'localhost'
SERVER_PORT = 9091
DEVICES_NUM = 1
MESSAGES_NUM = 2
ID_OF_FIRST = 200
TEST_SCENARIO = 'start_client'

class SensoryDevice:
    def __init__(self, device_id, server_ip, server_port):
        self.device_id = device_id
        self.gateway_address = (server_ip, server_port)  # Gateway address and port
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.authenticationManager = AuthenticationManager()
        self.authenticationManager.generete_key_pair()

    def __del__(self):
        try:
            self.socket.close()
            print("Sensory device " + str(self.device_id) + " closed socket successfully.")
        except socket.error as e:
            print(f"Error while closing the socket: {e}")


    def send_register_message(self) -> None:
        public_key_pem = self.authenticationManager.get_public_key_pem()

        register_message = {
            "action": "register",
            "device_id": self.device_id,
            "public_key": public_key_pem,
            "device_type": "sensor"
        }

        register_message = cbor2.dumps(register_message)

        self.socket.sendto(register_message, self.gateway_address)
        print(f'Sent register message from device {self.device_id}')

        while True:

            confirmation = self.socket.recvfrom(1024)[0]

            json_confirmation = cbor2.loads(confirmation)
            if json_confirmation["action"] != "register_confirmation" or json_confirmation["device_type"] != "sensor":
                continue
            if json_confirmation["status"]:
                print(f"Registration of {self.device_id} succesfull")
            else:
                print(f"Registration of {self.device_id} unsuccesfull")
            return

    def send_unregister_message(self) -> None:
        signature = self.authenticationManager.sign_message(self.device_id)

        unregister_message = {
            "action": "unregister",
            "device_id": self.device_id,
            "device_type": "sensor",
            "signature": signature
        }

        unregister_message = cbor2.dumps(unregister_message)

        self.socket.sendto(unregister_message, self.gateway_address)
        print(f'Sent unregister message from device {self.device_id}')

        while True:

            confirmation = self.socket.recvfrom(1024)[0]

            json_confirmation = cbor2.loads(confirmation)
            if json_confirmation["action"] != "unregister_confirmation" or json_confirmation["device_type"] != "sensor":
                continue
            if json_confirmation["status"]:
                print(f"Unregistration of {self.device_id} succesfull")
            else:
                print(f"Unregistration of {self.device_id} unsuccesfull")
            return

    def send_data(self, messages_num, duplication=False, wrong_signature=False):
        for i in range(messages_num):
            time.sleep(3 + random.random())

            random_data = random.randint(0, 1000)
            signature = self.authenticationManager.sign_message(random_data)

            data = {
                "action": "send_data",
                "device_id": self.device_id,
                "sensor_data": random_data,
                "signature": signature
                }
            if wrong_signature:
                data['signature'] = self.authenticationManager.sign_message(123456)
            cbor_data = cbor2.dumps(data)
            print(f"data value: {random_data}")
            print(f"data to be sent in cbor format: {cbor_data}")
            self.socket.sendto(cbor_data, self.gateway_address)
            if duplication:
                self.socket.sendto(cbor_data, self.gateway_address)
                print(f"data value: {random_data}")
                print(f"data to be sent in cbor format: {cbor_data}")

    def communicate_with_gateway_without_registration(self, messages_num):
        self.send_data(messages_num)
        self.send_unregister_message()

    def communicate_with_gateway_with_registration(self, messages_num):
        self.send_register_message()
        self.send_data(messages_num)
        self.send_unregister_message()


class SenosryDeviceManager:
    def __init__(self, devices_num, messages_num, server_ip, server_port, id_of_first, test_scenario):
        self.devices_num = devices_num
        self.messages_num = messages_num
        self.server_ip = server_ip
        self.server_port = server_port
        self.id_of_first = id_of_first
        self.threads_list = []
        self.test_scenario = test_scenario

    def start_devices_in_threads(self):
        for i in range(self.devices_num):
            thread = Thread(target=self.test_scenario, args=(self.id_of_first + i,
                                                       self.messages_num,
                                                       self.server_ip, self.server_port))
            self.threads_list.append(thread)
            thread.start()
            time.sleep(1)

        for thread in self.threads_list:
            thread.join()


def start_client(device_id, messages_num, server_ip, server_port):
    sensory_device = SensoryDevice(device_id, server_ip, server_port)
    sensory_device.communicate_with_gateway_with_registration(messages_num)


def send_msg_without_reg(device_id, messages_num, server_ip, server_port):
    sensory_device = SensoryDevice(device_id, server_ip, server_port)
    sensory_device.communicate_with_gateway_without_registration(messages_num)

def same_mess(device_id, messages_num, server_ip, server_port):
    sensory_device = SensoryDevice(device_id, server_ip, server_port)
    sensory_device.send_register_message()
    sensory_device.send_data(messages_num, duplication=True)
    sensory_device.send_unregister_message()

def wrong_signature(device_id, messages_num, server_ip, server_port):
    sensory_device = SensoryDevice(device_id, server_ip, server_port)
    sensory_device.send_register_message()
    sensory_device.send_data(messages_num, wrong_signature=True)
    sensory_device.send_unregister_message()

def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--address", default=SERVER_IP,
                        help="ip address of the server")
    parser.add_argument("-p", "--port", default=SERVER_PORT,
                        help="port of the server")
    parser.add_argument("-dn", "--devices_num", default=DEVICES_NUM,
                        help="number of sensory devices")
    parser.add_argument("-mn", "--messages_num", default=MESSAGES_NUM,
                        help="number of messages to send from a sensory device")
    parser.add_argument("-id", "--id_of_first", default=ID_OF_FIRST,
                        help="id of the first sensory device")
    parser.add_argument("-t", "--test", default=TEST_SCENARIO,
                        help="choosen test scenario")
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()
    test_function = globals().get(args.test)
    manager = SenosryDeviceManager(int(args.devices_num), int(args.messages_num), args.address, int(args.port), int(args.id_of_first), test_function)
    manager.start_devices_in_threads()


if __name__ == "__main__":
    main()

