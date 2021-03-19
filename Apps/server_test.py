#!/usr/bin/env python3

import socket
import sys


port = 5000

newport = 13377

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind(("127.0.0.1",port))
    print("Listening on port ",port)
    #while True:
    data,addr = s.recvfrom(1024)
    print("Data:",data)
    print("Addr",addr)

    msg=int.from_bytes(data,sys.byteorder)
    print("Recived",msg)

    s.sendto(newport.to_bytes(2,sys.byteorder),addr)
