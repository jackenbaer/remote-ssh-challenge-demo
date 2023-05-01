import paramiko
import time





if __name__ == "__main__":
    agent = paramiko.Agent()
    for key in agent.get_keys():
        print(f'key_type = {key.get_name()}, pub = {key.asbytes().hex()}, fingerprint = {key.get_fingerprint().hex()}')

