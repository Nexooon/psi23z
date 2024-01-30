#Nazwa projektu: CyBORgi
#Autorzy pliku: Filip Browarny, Krzysztof Kluczyński, Hubert Brzóskniewicz, Kamil Kułak
import json
from threading import Thread
import cbor2
import socket
import argparse
from datetime import datetime
from typing import Tuple, Dict
from authenticationManager import AuthenticationManager
import base64
from collections import deque

GATEWAY_IP = 'localhost'
GATEWAY_PORT = 9091
HISTORY_LEN = 10

class CommunicationGateway:
    def __init__(self, ip, port, history_len):
        self.active_devices: Dict[int, Tuple[Tuple[str, int], str]] = {}
        self.active_recorders: Dict[int, Tuple[Tuple[str, int], str]] = {}
        self.server_ip = ip
        self.server_port = port
        self.history = deque(maxlen=history_len)
        self.authenticationManager = AuthenticationManager()
        self.authenticationManager.generete_key_pair()

    def _send_reg_confirmation(self, action, device_id, device_type, status_bool, address: Tuple[str, int]):
        register_confirmation = {
            "action": action,
            "device_id": device_id,
            "device_type": device_type,
            "status": status_bool,
            "public_key": self.authenticationManager.get_public_key_pem().decode('utf-8')
        }
        if device_type == "sensor":
            print(register_confirmation)
            self.send_data_to_specific_sensor(register_confirmation, address)
        else:
            register_confirmation = json.dumps(register_confirmation)
            self.send_data_to_specific_recorder(register_confirmation, address)

    def _register(self, device_id, device_type, address: Tuple[str, int], public_key) -> None:
        if device_type == "sensor":
            if device_id in self.active_devices.keys():
                msg = f"Device {device_id} already registered\n\n\n"
                print(msg)
                self._send_reg_confirmation("register_confirmation", device_id, "sensor", 0, address)
                return

            if address in self.active_devices.values():
                msg = f"Device with address {address} already registered\n\n\n"
                print(msg)
                self._send_reg_confirmation("register_confirmation", device_id, "sensor", 0, address)
                return


            self.active_devices[device_id] = (address, public_key)
            self._send_reg_confirmation("register_confirmation", device_id, "sensor", 1, address)
            print(f"Registered sensor {device_id} with address {address[0]}:{address[1]}\n\n\n")

        else:
            if device_id in self.active_recorders.keys():
                msg = f"Device {device_id} already registered\n\n\n"
                print(msg)
                self._send_reg_confirmation("register_confirmation", device_id, "recorder", 0, address)
                return

            if address in self.active_recorders.values():
                msg = f"Device with address {address[0]} already registered\n\n\n"
                print(msg)
                self._send_reg_confirmation("register_confirmation", device_id, "recorder", 0, address[0])
                return


            self.active_recorders[device_id] = (address, public_key)
            self._send_reg_confirmation("register_confirmation", device_id, "recorder", 1, address)
            print(f"Registered recorder {device_id} with address {address[0]}:{address[1]}\n\n\n")

    def _unregister(self, device_id, device_type) -> None:

        if device_type == 'sensor':
            device_adress = self.active_devices[device_id][0]
            if device_id not in self.active_devices.keys():
                msg = f"Can't unregister {device_type} device {device_id} because it is not registered\n\n\n"
                print(msg)
                self._send_reg_confirmation("unregister_confirmation", device_id, "sensor", 0, device_adress)
                return

            self.active_devices.pop(device_id)
            print(f"Unregistered device {device_id}\n\n\n")
            self._send_reg_confirmation("unregister_confirmation", device_id, "sensor", 1, device_adress)

        if device_type == 'recorder':
            device_adress = self.active_recorders[device_id][0]
            if device_id not in self.active_recorders.keys():
                msg = f"Can't unregister {device_type} device {device_id} because it is not registered\n\n\n"
                print(msg)
                self._send_reg_confirmation("unregister_confirmation", device_id, "recorder", 0, device_adress)
                return

            self.active_recorders.pop(device_id)
            print(f"Unregistered device {device_id}\n\n\n")
            self._send_reg_confirmation("unregister_confirmation", device_id, "recorder", 1, device_adress)

    def get_registered_devices(self):
        return self.active_devices

    def handle_message(self, address: Tuple[str, int], message) -> None:
        cbor_data = cbor2.loads(message)
        json_message = cbor_data

        print(f"received cbor data: {message}")
        print(f"converted json data: {json_message}")

        if json_message['action'] == "register":
            if json_message['device_type'] in ["sensor", "recorder"]:
                self._register(json_message['device_id'], json_message['device_type'], address, json_message['public_key'])
            else:
                print("Unknown device type wants to register")
        elif json_message['action'] == "unregister":
            if json_message['device_type'] in ["sensor", "recorder"]:
                self.handle_unregister_message(json_message['device_id'], json_message['device_id'],
                                               json_message["signature"], json_message['device_type'])
        elif json_message["action"] == "send_data":
            device_id = json_message['device_id']
            sensor_data = json_message['sensor_data']
            signature = json_message['signature']

            self.handle_send_message_data(device_id, sensor_data, signature)


    def handle_unregister_message(self, device_id, message, signature, device_type):
        if device_type == 'sensor':
            if device_id not in self.active_devices.keys():
                msg = f"Can't unregister device {device_id} because it is not registered\n\n\n"
                print(msg)
                return

            sensor_pub_key = self.active_devices.get(device_id)[1]
            if (self.check_signature(message, signature, sensor_pub_key)):
                self._unregister(device_id, device_type)
        else:
            if device_id not in self.active_recorders.keys():
                msg = f"Can't unregister device {device_id} because it is not registered\n\n\n"
                print(msg)
                return

            sensor_pub_key = self.active_recorders.get(device_id)[1]
            if (self.check_signature(message, signature, sensor_pub_key)):
                self._unregister(device_id, device_type)


    def handle_send_message_data(self, device_id, sensor_data, signature):
        if device_id not in self.active_devices.keys():
                print(f"YOU HAVE TO REGISTER YOUR DEVICE FIRST, DEVICE_ID = {device_id} NOT IN REGISTRY\n\n\n")
                return

        sensor_pub_key = self.active_devices.get(device_id)[1]
        if (self.check_signature(sensor_data, signature, sensor_pub_key)):
            current_daytime = datetime.now()
            timestamp = current_daytime.strftime("%Y-%m-%d %H:%M:%S")
            print(f"Current timestamp with date and hour: {timestamp}")

            signature = self.authenticationManager.sign_message(sensor_data)

            data_json = {
                "data": sensor_data,
                "timestamp": f"{timestamp}",
                "signature": base64.b64encode(signature).decode('utf-8')
            }
            print("about to dump", data_json)
            data_json = json.dumps(data_json)

            print(f"sent data: {data_json}")
            self.send_data_to_recorders(data_json)

        else:
            print("WRONG SIGNATURE!")
            return

    def check_signature(self, sensor_data, signature, sensor_pub_key):
        return self.authenticationManager.verify_signature(sensor_data, signature, sensor_pub_key)

    def start_udp_server(self):
        server_thread = Thread(target=self._udp_server, args=(self.server_ip, self.server_port))
        server_thread.start()

    def _udp_server(self, ip, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
            server_socket.bind((ip, port))
            print(f"UDP Server listening on {ip}:{port}")
            while True:
                data, addr = server_socket.recvfrom(1024)
                if data in self.history:
                    print(f"\n\n\nreceived duplicated message, skipping: {data}\n\n\n")
                    continue
                self.history.append(data)
                self.handle_message(addr, data)

    def send_data_to_recorders(self, json_data):
        for recorder_id in self.active_recorders:
            self.send_data_to_specific_recorder(json_data, self.active_recorders[recorder_id][0])

    def send_data_to_specific_recorder(self, json_data, recorder_address: Tuple[str, int]):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            client_socket.sendto(json_data.encode('utf-8'), recorder_address)
            print(f"Data sent to recorder at {recorder_address}\n\n\n")

    def send_data_to_specific_sensor(self, json_data, sensor_address):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            cbor_data = cbor2.dumps(json_data)
            client_socket.sendto(cbor_data, sensor_address)
            print(f"Data sent to sensor at {sensor_address}\n\n\n")


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--address", default=GATEWAY_IP,
                        help="ip address of the gateway")
    parser.add_argument("-p", "--port", default=GATEWAY_PORT,
                        help="port of the server")
    parser.add_argument("-hl", "--history_len", default=HISTORY_LEN,
                        help="number of messages in history log")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    gateway = CommunicationGateway(ip=args.address, port=int(args.port), history_len=int(args.history_len))
    gateway.start_udp_server()


if __name__ == "__main__":
    main()
