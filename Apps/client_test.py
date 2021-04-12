#!/usr/bin/env python3

import socket
import sys



rhost = "192.168.50.250"
rport = 2525


message = 0x6162
msg_enc = message.to_bytes(2,'big')
#int.from_bytes(msg,sys.byteorder)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:

    # Ask for port based on watermark
	s.sendto(msg_enc, (rhost, rport))

    # Receive port from controller
	new_port,addr=s.recvfrom(1024)

	print("Recived new port:",int.from_bytes(new_port,'big'))
	s.close()
