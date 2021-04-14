#!/usr/bin/env python3

from mininet.topo import Topo
class SimpleNat( Topo ):
    def __init__( self ):

        # Initialize topology
        Topo.__init__( self )

        # Routers
        r = self.addSwitch('r',dpid='000000000001', listenPort='6634')

        # Hosts
        sdb = self.addHost('sdb', ip='192.168.50.100/24', defaultRoute = "via 192.168.50.1", mac='aa:aa:aa:aa:aa:aa')
        si = self.addHost('si', ip='192.168.150.100/24', defaultRoute = "via 192.168.150.1", mac='aa:aa:aa:aa:aa:bb')
        so = self.addHost('so', ip='192.168.200.100/24', defaultRoute = "via 192.168.200.1", mac='aa:aa:aa:aa:aa:cc')

        # Hosts placement
        self.addLink(sdb, r, port1=0, port2=1)
        self.addLink(si, r, port1=0, port2=2)
        self.addLink(so, r, port1=0, port2=3)

topos = { 'SimpleNat': ( lambda: SimpleNat() ) }