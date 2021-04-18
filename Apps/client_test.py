#!/usr/bin/env python3

import socket
import sys
import watermark


natSrvIP = "192.168.50.250"
natSrvPort = 2525


def sendImage(path):
	w = watermark.Watermarker(path)
	wm = w.checkWM()

	# Set up a socket that will connect to application
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as appSrv:

		# Used to get the port the OS alocated for socket
		appSrv.bind(('',0))
		localPort = appSrv.getsockname()[1]
		print("Recived from OS ",localPort," as free port")

		# We add the port to the payload
		natPayload = localPort.to_bytes(2,'big')
		natPayload += wm.to_bytes(16,'big')

		# Link to application port that will be given by NAT server
		appPort = None

		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as natSrv:

			# Ask for port based on watermark
			natSrv.sendto(natPayload, (natSrvIP, natSrvPort))

			# Receive port from controller
			appPort,_=natSrv.recvfrom(1024)
			appPort = int.from_bytes(appPort,'big')

			print("Recived new port form NAT:",appPort)


		
		# Send files to processing server
		print("Sending ",path)
		with open(path,'rb') as file:
			appSrv.connect((natSrvIP,appPort))
			
			part = file.read(1024)
			while part:
				appSrv.send(part)
				part = file.read(1024)
		print("Client done.")

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print("Usage: client_test.py path_to_file")
	sendImage(sys.argv[1])