from pox.core import core
import time
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str

# Logging
log = core.getLogger()


sdb="192.168.50.100"
si ="192.168.150.100"
so ="192.168.200.100"


class Controller(object):
	NUMBER_OF_ROUTERS = 1

	def __init__(self,connection):
		self.connection = connection
		connection.addListeners(self)

		# {ip:[port:mac]}
		self.arpTable=[{
		sdb:[1,"aa:aa:aa:aa:aa:aa"], 	#192.168.50.100
		si:[2,"11:11:11:11:11:11"],		#192.168.150.100
		so:[3,"99:99:99:99:99:99"]		#192.168.200.100
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

	# ref: https://openflow.stanford.edu/display/ONL/POX+Wiki.html#POXWiki-Example%3AARPmessages
	def arp(self, packet, data, r):
		log.debug("Arp request detected to %r"%str(packet.payload.protodst))
		arp_packet = packet.payload
		if arp_packet.opcode == pkt.arp.REQUEST:
			# For each subnet in the router 'r'
			for k in self.routingPorts[r]["subnets"]:
				subIP = self.routingPorts[r]["subnets"][k]['ip']
				# Directed to router for the specific subnet
				if str(arp_packet.protodst) == subIP:
					# Forge ARP Reply
					# ARP
					arp_reply = pkt.arp()
					arp_reply.hwsrc = adr.EthAddr(self.routingPorts[r]['mac'])
					arp_reply.hwdst = arp_packet.hwsrc
					arp_reply.opcode = pkt.arp.REPLY
					arp_reply.protosrc = arp_packet.protodst
					arp_reply.protodst = arp_packet.protosrc
					# Ethernet
					eth_packet = pkt.ethernet()
					eth_packet.type = pkt.ethernet.ARP_TYPE
					eth_packet.dst = packet.src
					eth_packet.src = adr.EthAddr(self.routingPorts[r]['mac'])
					eth_packet.payload = arp_reply

					msg = of.ofp_packet_out()
					msg.data = eth_packet.pack()

					action = of.ofp_action_output(port = data.in_port)
					msg.actions.append(action)
					self.connection.send(msg)

					self.arpTable[r][arp_packet.protodst] = [data.in_port, packet.src]
					log.debug("Sending ARP reply: %r -> %r"%(str(arp_reply.hwsrc),subIP))

				else:
					# Ignore. In our topology each port coresponds to a subnet
					pass

		elif arp_packet.opcode == pkt.arp.REPLY:
			log.debug("Received ARP REPLY. Adding to ARP table")
			self.arpTable[r][packet.src] = [data.in_port, packet.src]
			# ! Can pe poisoned if handeled this way


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
			log.debug("Next hop not found. No where forward packet.")

		return (macNext,portNext)


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

	def routeMsg(self, packet, data, macNext, portNext):
		log.debug("Routing message without flow from %r to %r."%(str(packet.src),str(packet.dst)))
		# Change the mac destination to the next device's address
		packet.dst = macNext
		# Change the mac of the source with the router's mac
		packet.src = packet.dst
		msg = of.ofp_packet_out()
		msg.data = packet.pack()
		msg.actions.append(of.ofp_action_output(port = portNext))
		self.connection.send(msg)


	def router(self, packet, data, r):
		ipDst = packet.payload.dstip
		ipSrc = packet.payload.srcip
		# Packet is reffered to a subnetwork from the router
		(macNext,portNext) = self.findRoute(ipSrc,ipDst,data.in_port, r)

		# If there is a route
		if macNext and portNext:
			self.routeMsgFlow(packet, data, macNext, portNext)
		elif portNext:
			self.blockMsgFlow(packet, data, inPort=portNext)


	def forwardIPPacket(self, packet, data, r):
		ipDst = packet.payload.dstip
		ipSrc = packet.payload.srcip
		log.debug("Got packet srcIP:%s with macSrc:%s TO dstIP:%s macDst:%s"%(ipSrc,str(packet.src),ipDst,str(packet.dst)))

		ipPacket = packet.payload

		# Check if the packet is a ping to router
		pingToRouter = False
		if ipPacket.protocol == pkt.ipv4.ICMP_PROTOCOL:
			for k in self.routingPorts[r]["subnets"]:
				if self.routingPorts[r]["subnets"][k]["ip"] == ipDst:
					pingToRouter = True

		# Ping to the router
		if pingToRouter:
			icmp_packet = ipPacket.payload
			if icmp_packet.type == pkt.TYPE_ECHO_REQUEST:
				log.debug("Recived icmp request to router %r. Sending echo reply."%str(ipDst))
				echo = pkt.echo()
				echo.seq = icmp_packet.payload.seq + 1
				echo.id = icmp_packet.payload.id

				icmp_reply = pkt.icmp()
				icmp_reply.type = pkt.TYPE_ECHO_REPLY
				icmp_reply.payload = echo

				ip_p = pkt.ipv4()
				ip_p.srcip = ipDst
				ip_p.dstip = ipSrc
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
		# Any other packet
		else:
			if self.routingPorts[r]["mac"] == str(packet.dst):
				self.router(packet, data, r)



	def _handle_PacketIn(self,event):
		log.debug("\nEvent from: %r"%dpid_to_str(event.dpid))
		packet = event.parsed
		if not packet.parsed:
			log.warning("Incomplete packet. Ignored.")
			return
		data = event.ofp
		if dpid_to_str(event.dpid) not in self.switchDPID.keys():
			log.debug("ERROR: Unexpected event DPID:"+ dpid_to_str(event.dpid))
			return
		r = self.switchDPID[dpid_to_str(event.dpid)]

		# ARP
		if packet.type == pkt.ethernet.ARP_TYPE:
			self.arp(packet,data,r)
		# IP
		elif packet.type == pkt.ethernet.IP_TYPE:
			self.forwardIPPacket(packet,data,r)

def launch ():
	def start_switch (event):
		log.debug("Controlling %s" % (event.connection,))
		Controller(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)