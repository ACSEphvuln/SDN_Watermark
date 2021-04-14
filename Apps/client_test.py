#!/usr/bin/env python3

import socket
import sys



natSrvIP = "192.168.50.250"
natSrvPort = 2525


wm = b"Aplicatii Multimedia"


# Set up a socket that will connect to application
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as appSrv:

	# Used to get the port the OS alocated for socket
	appSrv.bind(('',0))
	localPort = appSrv.getsockname()[1]
	print("Recived from OS ",localPort," as free port")

	# We add the port to the payload
	natPayload = localPort.to_bytes(2,'big')
	natPayload += wm

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
	appSrv.connect((natSrvIP,appPort))
	appSrv.send(b"AAAA-1337-7331-AAAA") # TEST 
	'''
		TODO client upload logic
	'''

