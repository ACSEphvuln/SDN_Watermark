#!/usr/bin/env python3

import socket
import sys


port = 13377

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.bind(('',port))
	s.listen(10)

	while True:
		conn,addr = s.accept()
		data = conn.recv(1024)
		print(data)
		'''
			TODO server download logic
		'''
		break


