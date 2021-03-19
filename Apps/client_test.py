#!/usr/bin/env python3

import socket
import sys



rhost = "127.0.0.1"
rport = 5000


nb = 65440
msg = nb.to_bytes(2,sys.byteorder)
#int.from_bytes(msg,sys.byteorder)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
	s.sendto(msg, (rhost, rport))
	new_port,addr=s.recvfrom(1024)

	print("Recived new port:",int.from_bytes(new_port,sys.byteorder))
