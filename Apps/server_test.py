#!/usr/bin/env python3

import socket
import sys
import random


port = 13377
def getImages(serverName):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.bind(('',port))
		s.listen(10)

		while True:
			conn,addr = s.accept()
			

			# Random file name
			with open(serverName+"/"+str(random.randrange(1000000000000,10000000000000))+'.png','wb') as file:
				data = conn.recv(1024)
				while data:
					file.write(data)
					data = conn.recv(1024)
				print("Got new image as ",file.name)

			conn.close()

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print("Usage: server_test.py SI|SO")
	getImages(sys.argv[1])