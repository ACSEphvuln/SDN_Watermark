from pox.core import core
import time
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str

import random

# Logging
log = core.getLogger()


sdb="192.168.50.100"
si ="192.168.150.100"
so ="192.168.200.100"
siso_port = 12345
app_port = 13377

# ref: https://github.com/Ephvuln/SNM_SDN
# Base controller functions
class ControllerBase(object):
	def __init__(self,connection):
		self.arpTable=None
		self.routingPorts=None


	def forge_arp_reply(self,arp_packet,data,smac,rmac):
		# ARP
		arp_reply = pkt.arp()
		arp_reply.hwsrc = adr.EthAddr(rmac)
		arp_reply.hwdst = arp_packet.hwsrc
		arp_reply.opcode = pkt.arp.REPLY
		arp_reply.protosrc = arp_packet.protodst
		arp_reply.protodst = arp_packet.protosrc
		# Ethernet
		eth_packet = pkt.ethernet()
		eth_packet.type = pkt.ethernet.ARP_TYPE
		eth_packet.dst = smac
		eth_packet.src = adr.EthAddr(rmac)
		eth_packet.payload = arp_reply

		msg = of.ofp_packet_out()
		msg.data = eth_packet.pack()

		action = of.ofp_action_output(port = data.in_port)
		msg.actions.append(action)
		self.connection.send(msg)


	# ref: https://openflow.stanford.edu/display/ONL/POX+Wiki.html#POXWiki-Example%3AARPmessages
	def arp(self, packet, data, r):
		log.debug("Arp request detected to %r"%str(packet.payload.protodst))
		arp_packet = packet.payload
		if arp_packet.opcode == pkt.arp.REQUEST:
			# For each subnet in the router 'r'
			for k in self.routingPorts[r]["subnets"]:
				subIP = self.routingPorts[r]["subnets"][k]['ip']
				# Directed to router for the specific subnet or special IP
				if str(arp_packet.protodst) == subIP:
					# Forge ARP Reply
					
					self.forge_arp_reply(arp_packet,data,smac=packet.src,rmac=self.routingPorts[r]['mac'])

					self.arpTable[r][arp_packet.protodst] = (data.in_port, packet.src)
					log.debug("Sending ARP reply: %r -> %r"%(str(arp_packet.hwsrc),subIP))
					return;
				else:
					# Ignore. In our topology each port coresponds to a subnet
					log.debug("Could not figure out arp reply")

		elif arp_packet.opcode == pkt.arp.REPLY:
			pass


	def forge_ping_reply(self,packet,data):
		icmp_packet = packet.payload.payload
		
		echo = pkt.echo()
		echo.seq = icmp_packet.payload.seq + 1
		echo.id = icmp_packet.payload.id

		icmp_reply = pkt.icmp()
		icmp_reply.type = pkt.TYPE_ECHO_REPLY
		icmp_reply.payload = echo

		ip_p = pkt.ipv4()
		ip_p.srcip = packet.payload.dstip
		ip_p.dstip = packet.payload.srcip
		ip_p.protocol = pkt.ipv4.ICMP_PROTOCOL
		ip_p.payload = icmp_reply

		eth_p = pkt.ethernet()
		eth_p.type = pkt.ethernet.IP_TYPE

		# Resend to previous route
		eth_p.dst = packet.src
		eth_p.src = packet.dst
		eth_p.payload = ip_p

		msg = of.ofp_packet_out()
		msg.data = eth_p.pack()
		action = of.ofp_action_output(port = data.in_port)
		msg.actions.append(action)

		self.connection.send(msg)


	def routeMsgFlow(self, packet, data, macNext, portNext):
		log.debug("Added flow from %r to %r."%(str(packet.src),str(packet.dst)))

		msg = of.ofp_flow_mod()

		msg.match.dl_type = pkt.ethernet.IP_TYPE
		msg.match.dl_dst = packet.dst
		msg.match.nw_src = packet.payload.srcip
		msg.match.nw_dst = packet.payload.dstip
		msg.match.in_port = data.in_port
		msg.data = data
		# Change the mac destination to the next device's address
		msg.actions.append(of.ofp_action_dl_addr.set_dst(macNext))
		# Change the mac of the source with the router's mac
		msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
		# Forward to the specified port
		msg.actions.append(of.ofp_action_output(port = portNext))
		self.connection.send(msg)


	def routeMsg(self, packet, macNext, portNext):
		log.debug("Routing message without flow from %r to %r."%(str(packet.src),str(packet.dst)))
		# Change the mac destination to the next device's address
		packet.dst = macNext
		# Change the mac of the source with the router's mac
		packet.src = packet.dst
		msg = of.ofp_packet_out()
		msg.data = packet.pack()
		msg.actions.append(of.ofp_action_output(port = portNext))
		self.connection.send(msg)


	def findRoute(self,ipSrc,ipDst, inPort , r):
		macNext = None
		portNext = None

		# Packet is reffered to a subnetwork from the router
		if str(ipDst) in self.arpTable[r]:
			for subnet in self.routingPorts[r]['subnets']:
				# Source and destination are not in the same subnet
				if ipDst.inNetwork(subnet):
					if not ipSrc.inNetwork(subnet):
						log.debug("Found direct route for to %r trough subnetwork %r."%(str(ipDst),subnet))

						macNext = EthAddr(self.arpTable[r][str(ipDst)][1])
						portNext = self.arpTable[r][str(ipDst)][0]

					else:
						log.debug("Packet came from the same subnet. Ignoring.")
		else:
			log.debug("Next hop not found. No where forward packet. Or packet directed to controller.")

		return (macNext,portNext)

	def routeIP(self, packet, data, r):
		ipDst = packet.payload.dstip
		ipSrc = packet.payload.srcip
		# Packet is reffered to a subnetwork from the router
		(macNext,portNext) = self.findRoute(ipSrc,ipDst,data.in_port, r)

		# If there is a route
		if macNext and portNext:
			self.routeMsgFlow(packet, data, macNext, portNext)



class Controller(ControllerBase):
	NUMBER_OF_ROUTERS = 1
	# Entry on port allocation
	CONTROLLER_IP = "192.168.50.250"
	CONTROLLER_PORT = 2525


	def __init__(self,connection):
		self.connection = connection
		connection.addListeners(self)

		# {ip:(port:mac)}
		self.arpTable=[
		{
			sdb:(1,"aa:aa:aa:aa:aa:aa"), 	#192.168.50.100
			si:(2,"aa:aa:aa:aa:aa:bb"),		#192.168.150.100
			so:(3,"aa:aa:aa:aa:aa:cc"),		#192.168.200.100
		}]


		self.routingPorts=[
		{   # Router1:
			"mac":"00:00:00:00:01:00",
			"subnets":{
				"192.168.50.0/24":{
					"port":1,
					"ip":"192.168.50.1"
				},
				"192.168.150.0/24":{
					"port":2,
					"ip":"192.168.150.1"
				},
				"192.168.200.0/24":{
					"port":3,
					"ip":"192.168.200.1"
				}
			}
		}]

		# Assign DPID to each router
		self.switchDPID={
			"00-00-00-00-00-01":0,
		}

		self.natTable={
		# (src_ip, port_in) : (dst_ip, port_out, exp_time)

		}

		# Time untill port forcefully frees
		self.natMaxTime = 20000

		self.serverDecision = 0

		self.localWMKeys = [
			0xbeef
		]



	def forge_udp(self,packet,data,payload,payload_len):

		# UDP
		payload = payload.to_bytes(payload_len,'big')
		udp_packet = pkt.udp()
		udp_packet.srcport = packet.payload.payload.dstport
		udp_packet.dstport = packet.payload.payload.srcport
		udp_packet.payload = payload

		# IP
		ipv4_packet = pkt.ipv4()
		ipv4_packet.iplen = pkt.ipv4.MIN_LEN + len(udp_packet)
		ipv4_packet.protocol = pkt.ipv4.UDP_PROTOCOL
		ipv4_packet.dstip = packet.payload.srcip
		ipv4_packet.srcip = packet.payload.dstip
		ipv4_packet.set_payload(udp_packet)

		# Ethernet
		eth_packet = pkt.ethernet()
		eth_packet.set_payload(ipv4_packet)
		eth_packet.dst = packet.src
		eth_packet.src = packet.dst
		eth_packet.type = pkt.ethernet.IP_TYPE

		msg = of.ofp_packet_out()
		msg.data = eth_packet.pack()

		msg.actions.append(of.ofp_action_output(port = data.in_port))
		self.connection.send(msg)


	def cleanNAT(self):
		# Delete based on time
		ctime= time.time()
		for k in  tuple(self.natTable.keys()):
			if self.natTable[k][2] >= ctime:
				self.natTable.pop(k)


	def findRouteIP(self,ipSrc,ipDst, inPort , r):
		macNext = None
		portNext = None
		troughIP = None

		# Packet is reffered to a subnetwork from the router
		if str(ipDst) in self.arpTable[r]:
			for subnet in self.routingPorts[r]['subnets']:
				# Source and destination are not in the same subnet
				if ipDst.inNetwork(subnet):
					if not ipSrc.inNetwork(subnet):
						log.debug("Found direct route for to %r trough subnetwork %r."%(str(ipDst),subnet))

						macNext = EthAddr(self.arpTable[r][str(ipDst)][1])
						portNext = self.arpTable[r][str(ipDst)][0]
						troughIP = self.routingPorts[r]['subnets'][subnet]['ip']

					else:
						log.debug("Packet came from the same subnet. Ignoring.")
		else:
			log.debug("Next hop not found. No where forward packet. Or packet directed to controller.")

		return (macNext,portNext,troughIP)


	def computeWMTraffic(self, packet, data, r):
		self.cleanNAT()


		srcIP = packet.payload.srcip
		srcMac = packet.src

		msg = packet.payload.payload.payload
		srcPrt = int.from_bytes(msg[0:2],'big')
		key = msg[2:]


		if key in self.localWMKeys:
			dstIP = si
			self.serverDecision = 1 # prioritize outside servers next
		else:
			# Round robin spread
			if self.serverDecision == 0:
				dstIP = si
			else:
				dstIP = so
			self.serverDecision = 1 - self.serverDecision


		#Find route
		(macNext,portNext,troughIP)=self.findRouteIP(srcIP,IPAddr(dstIP), data.in_port , r)
		if macNext == None:
			log.debug("NAT request, bad route. Ignoring.")
			return

		# Find free port
		traffic_port = random.randint(20000,30000)
		initial_port = traffic_port

		portFound = False
		while traffic_port < 30000:
			if (srcIP,traffic_port) in self.natTable:
				traffic_port += 1
			else:
				portFound = True
				break 
		if not portFound:
			while traffic_port < initial_port:
				if (srcIP,traffic_port) in self.natTable:
					traffic_port += 1
				else:
					portFound = True
					break 
		if not portFound:
			log.debug("ERR: All NAT ports occupied for %r."%str(srcIP))
			return 


		maxtime= time.time()+self.natMaxTime

		# client - server
		flow = of.ofp_flow_mod()
		flow.hard_timeout = self.natMaxTime
		flow.match.nw_proto =  pkt.ipv4.TCP_PROTOCOL
		flow.match.dl_type = pkt.ethernet.IP_TYPE
		flow.match.dl_dst = packet.dst
		flow.match.dl_src = packet.src 
		flow.match.nw_src = packet.payload.srcip
		flow.match.nw_dst = Controller.CONTROLLER_IP
		flow.match.tp_src =  srcPrt
		flow.match.tp_dst = traffic_port
		flow.match.in_port = data.in_port
		flow.actions.append(of.ofp_action_dl_addr.set_src(self.routingPorts[r]['mac']))
		flow.actions.append(of.ofp_action_dl_addr.set_dst(macNext))
		flow.actions.append(of.ofp_action_nw_addr.set_src(Controller.CONTROLLER_IP))
		flow.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(dstIP)))
		flow.actions.append(of.ofp_action_tp_port.set_src(traffic_port))
		flow.actions.append(of.ofp_action_tp_port.set_dst(app_port))
		flow.actions.append(of.ofp_action_output(port = portNext))
		self.connection.send(flow)

		self.natTable[(srcIP,traffic_port)]=(dstIP,app_port,maxtime)

		
		# server - client
		flow = of.ofp_flow_mod()
		flow.hard_timeout = self.natMaxTime
		flow.match.nw_proto =  pkt.ipv4.TCP_PROTOCOL
		flow.match.dl_type = pkt.ethernet.IP_TYPE
		flow.match.dl_dst = packet.dst
		flow.match.dl_src = macNext
		flow.match.nw_src = IPAddr(dstIP)
		flow.match.nw_dst = Controller.CONTROLLER_IP
		flow.match.tp_dst = traffic_port
		flow.match.tp_src = app_port
		flow.match.in_port = portNext
		flow.actions.append(of.ofp_action_dl_addr.set_src(self.routingPorts[r]['mac']))
		flow.actions.append(of.ofp_action_dl_addr.set_dst(srcMac))
		flow.actions.append(of.ofp_action_nw_addr.set_src(Controller.CONTROLLER_IP))
		flow.actions.append(of.ofp_action_nw_addr.set_dst(srcIP))
		flow.actions.append(of.ofp_action_tp_port.set_src(traffic_port))
		flow.actions.append(of.ofp_action_tp_port.set_dst(srcPrt))
		flow.actions.append(of.ofp_action_output(port = data.in_port))
		self.connection.send(flow)

		self.natTable[(dstIP,app_port)]=(srcIP,traffic_port,maxtime)

		log.debug("Sending nat reply to %r at free port %r \n"%(str(packet.payload.srcip),str(traffic_port)))
		self.forge_udp(packet,data,traffic_port,16)




	def handleIP(self, packet, data, r):
		ipDst = packet.payload.dstip
		ipSrc = packet.payload.srcip
		log.debug("Got packet srcIP:%s macSrc:%s TO dstIP:%s macDst:%s"%(ipSrc,str(packet.src),ipDst,str(packet.dst)))

		ipPacket = packet.payload

		# Check if the packet is a ping to router
		pingToRouter = False
		if ipPacket.protocol == pkt.ipv4.ICMP_PROTOCOL:
			for k in self.routingPorts[r]["subnets"]:
				if self.routingPorts[r]["subnets"][k]["ip"] == ipDst:
					pingToRouter = True
					break

		# Ping to the router
		if pingToRouter:
			if packet.payload.payload.type == pkt.TYPE_ECHO_REQUEST:
				log.debug("Recived ping to router %r. Sending echo reply."%str(ipDst))
				self.forge_ping_reply(packet,data)
		# Any other packet
		elif self.routingPorts[r]["mac"] == str(packet.dst):
			# Controller features
			if packet.payload.dstip == Controller.CONTROLLER_IP:
				if packet.payload.protocol == pkt.ipv4.ICMP_PROTOCOL:
					if packet.payload.payload.type == pkt.TYPE_ECHO_REQUEST:
						self.forge_ping_reply(packet,data)
				elif packet.payload.payload.dstport == Controller.CONTROLLER_PORT \
						and packet.payload.protocol == pkt.ipv4.UDP_PROTOCOL:
					self.computeWMTraffic(packet, data, r)
			# Normal traffic 
			else:
				self.routeIP(packet, data, r)


	# Packet to controller 
	def _handle_PacketIn(self,event):
		log.debug("\nEvent from: %r"%dpid_to_str(event.dpid))
		# Forwarded packet:
		packet = event.parsed
		if not packet.parsed:
			log.warning("Incomplete packet. Ignored.")
			return

		# Of packet data
		data = event.ofp
		if dpid_to_str(event.dpid) not in self.switchDPID.keys():
			log.debug("ERROR: Unexpected event DPID:"+ dpid_to_str(event.dpid))
			return

		# Identify router
		r = self.switchDPID[dpid_to_str(event.dpid)]

		# ARP
		if packet.type == pkt.ethernet.ARP_TYPE:
			# Request for network features:
			if  str(packet.payload.protodst) in (Controller.CONTROLLER_IP):
				self.forge_arp_reply(arp_packet=packet.payload,data=data,smac=packet.src,rmac=self.routingPorts[r]['mac'])
			else:
				# Normal ARP
				self.arp(packet,data,r)
		# IP
		elif packet.type == pkt.ethernet.IP_TYPE:
			self.handleIP(packet,data,r)
		else:
			log.debug("Could not understand request.")





# Controller start
def launch ():
	def start_switch (event):
		log.debug("Controlling %s" % (event.connection,))
		Controller(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)