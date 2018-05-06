# Copyright 2011,2012,2013,2017 James McCauley
# Copyright 2018 Yating Zhou (aka syscl), John, Navjot
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import pox.lib.packet as pkt
# syscl - for poisson distribution
# refer here: 
# https://docs.scipy.org/doc/numpy-1.14.0/reference/generated/numpy.random.poisson.html
# to import numpy, you should install the following:
# sudo apt-get install python-pip  
# sudo pip install numpy
import numpy as np
#
# package for log out time
# 
import time
import datetime
from time import gmtime, strftime
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

#
# MAC Header (Ethernet II):  
# 14 bytes = dst MAC (6 bytes/octets) + src MAC (6 bytes) + Ether Type (08 00)
#

#
# msglog: tidy information output
# status: string, "OK", "FAIL", "NOTE"
# message: string, the message you want to provide for users
# return void
#   
def msglog(status, message):
  OFF = '\033[0m'
  if status == "OK":
    color = '\033[1;32m'
    print "[{0}][ {1}{2}{3} ] {4}".format(datetime.datetime.now().time(), color, status, OFF, message)

  if status in ["NOTE", "FAIL"]:
    color = '\033[1;31m'
    print "[{0}][{1}{2}{3}] {4}".format(datetime.datetime.now().time(), color, status, OFF, message)

  if status == "--->":
    color = '\033[1;34m'
    print "[{0}][{1}{2}{3}] {4}".format(datetime.datetime.now().time(), color, status, OFF, message)

# Hosts hash table (Key, Value) = (HostIP, MAC)
hosts = {}

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
gFloodDelay = 0

# DHCP message handler
def _handle_dhcp_lease(event):
  msglog("OK", "DHCP packet from ({0}, {1})".format(event.ip, event.host_mac))
  # Add this IP and MAC to the hosts dictionary
  if event.ip != None and event.host_mac != None:
    hosts[str(event.ip)] = str(event.host_mac)
  msglog("OK", "Add host ({0}, {1}) to table (IP, MAC)".format(event.ip, event.host_mac))


class LearningSwitch (object):
  """
  The smart switch "brain" associated with a single OpenFlow switch.

  When we see a packet, we'd like to output it on a port which will
  eventually lead to the destination.  To accomplish this, we build a
  table that maps addresses to ports.

  We populate the table by observing traffic.  When we see a packet
  from some source coming from some port, we know that source is out
  that port.

  When we want to forward traffic, we look up the desintation in our
  table.  If we don't know the port, we simply send the message out
  all ports except the one it came in on.  (In the presence of loops,
  this is bad!).

  In short, our algorithm looks like this:

  For each packet from the switch:
  1) Use source address and switch port to update address/port table
  2) Is transparent = False and either Ethertype is LLDP or the packet's
     destination address is a Bridge Filtered address?
     Yes:
        2a) Drop packet -- don't forward link-local traffic (LLDP, 802.1x)
            DONE
  3) Is destination multicast?
     Yes:
        3a) Flood the packet
            DONE
  4) Port for destination address in our address/port table?
     No:
        4a) Flood the packet
            DONE
  5) Is output port the same as input port?
     Yes:
        5a) Drop packet and similar ones for a while
  6) Install flow table entry in the switch so that this
     flow goes out the appopriate port
     6a) Send the packet out appropriate port
  """
  def __init__ (self, connection, transparent):
    # Switch we'll be adding smart switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = gFloodDelay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

    # Now add entries for ARP traffic
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_type = pkt.ethernet.ARP_TYPE);
    msg.idle_timeout = of.OFP_FLOW_PERMANENT;
    msg.hard_timeout = of.OFP_FLOW_PERMANENT;
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self.connection.send(msg)
  
    # Add entries to intercept the DHCP traffic
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(nw_proto = 17, tp_src = 67 , tp_dst = 68);
    msg.idle_timeout = of.OFP_FLOW_PERMANENT;
    msg.hard_timeout = of.OFP_FLOW_PERMANENT;
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    msglog("OK", "Install flow entry.")

    # Register a handler for DHCP lease packets
    core.DHCPD.addListenerByName('DHCPLease', _handle_dhcp_lease)

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.

    class PacketIn in pox/openflow/__init__.py 
    ('Dir: ', ['__class__', 
    '__delattr__', '__dict__', '__doc__',  '__format__', 
    '__getattribute__', '__hash__', '__init__', '__module__', 
    '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', 
    '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_invoke', 
    '_parsed', 'connection', 'data', 'dpid', 'halt', 'ofp', 'parse', 'parsed', 
    'port', 'source'])
    ('type: ', <class 'pox.openflow.PacketIn'>)
    """
    packet = event.parsed

    def flood(message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= gFloodDelay:
        # Only flood if we've been connected for a little while...
        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          msglog("NOTE", "Found expired hold-down flood @{0}".format(event.dpid))
          msglog("--->", "Flooding...")

        if message is not None: 
          log.debug(message)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    def logARPInfo(aPacket):
      """
      print out the current ARP packet information
      """
      if packet.type == packet.ARP_TYPE:
        msglog("OK", "Source IP            : {0}".format(aPacket.payload.protosrc))
        msglog("OK", "Source MAC           : {0}".format(aPacket.payload.hwsrc))
        msglog("OK", "Source Destination IP: {0}".format(aPacket.payload.protodst))
        msglog("OK", "Destination MAC      : {0}".format(aPacket.dst))
      else:
        msglog("FAIL", "Not an ARP packet, type = {0}".format(packet.type))

    def arpPktShim(aPacket):
      """
      Check if ARP packet is valid
      If an ARP packet is valid, we pass it (i.e. do nothing) 
      otherwise we blacklist it for a while
      There is two type of arp packet we need to deal with:
      ARP Request vs ARP Reply, we handle them seperately
      """
      if aPacket.payload.opcode == pkt.arp.REQUEST:
        msglog("OK", "Found ARP request packet")
        if isARPPktInvalid(aPacket):
          # mitigate it here
          blockMAC(aPacket)
      elif aPacket.payload.opcode == pkt.arp.REPLY:
        # syscl - we should handle reply packet as well
        #TODO: Do we need to use possion for checking flooding message?
        msglog("OK", "Found ARP reply packet")
        if aPacket.dst in self.macToPort: 
          port = self.macToPort[aPacket.dst]
          if port == event.port:
            # log out the information first
            logARPInfo(aPacket)
            msglog("NOTE", "Drop packet {0} -> {1} on {2}@{3}".format(aPacket.src, aPacket.dst, dpid_to_str(event.dpid), port))
            # Yating - simply drop a packet will cause performance hit, thus
            # two ideas come into my mind: poisson checking vs blacklist
            blockMAC(aPacket)

    def isARPPktInvalid(aPacket):
      """
      Accroding to the propeties from ..., there is generally 4 cases we need to match against 
      """
      ret = False
      src_mac_eth = aPacket.src
      dst_mac_eth = aPacket.dst
      src_ip_arp  = aPacket.payload.protosrc
      src_mac_arp = aPacket.payload.hwsrc 
      dst_ip_arp  = aPacket.payload.protodst
      # log out the information for debug
      logARPInfo(aPacket)
      # the reason why we use such tedious log condition check here is 
      # because we also want to specific what type of ARP spoof it is 
      if src_mac_eth == src_mac_arp:
        if src_ip_arp not in hosts.keys():
          #for key in hosts.keys():
          #  print("Key: %s, Value: %s" %(key, hosts[key]))
          #print("table: ", hosts.keys())
          msglog("NOTE", "{0} is not in table.".format(src_mac_arp))
          ret = True
        else:
          msglog("OK", "{0} is in table.".format(src_mac_arp))
          if EthAddr(hosts[str(src_ip_arp)]) == src_mac_arp:
            if dst_ip_arp not in hosts.keys():
              # syscl - do we really need this?
              msglog("NOTE", "{0} not exist, found ARP Spoofing @{1}".format(dst_ip_arp, src_mac_eth))
              ret = True
          else:
            msglog("NOTE", "Found ARP Spoofing @{0} should be {1}".format(src_mac_eth, hosts[str(src_ip_arp)]))
            ret = True
      else:
        msglog("NOTE", "Found arp spoofing attack @{0}, should be {1}".format(src_mac_eth, src_mac_arp))
        ret = True
      # push back the result now
      return ret

    def blockMAC(aPacket):
      """
      Drop arp packet from current mac
      """
      mac     = aPacket.src
      timeout = 60 # unit: sec
      msglog("--->", "Generating blacklist to drop all packets from {0} for {1}s".format(mac, timeout))
      actions = []
      actions.append(of.ofp_action_output(port = of.OFPP_NONE)) # block packet
      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=timeout, 
                                hard_timeout=timeout, 
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=of.ofp_match.from_packet(aPacket,
                                                               event.port))
      event.connection.send(msg.pack())
      msglog("OK", "Generate blacklist for {0}".format(mac))

    def icmpPktShim(aPacket):
      src_mac_eth = aPacket.src
      dst_mac_eth = aPacket.dst
      msglog("OK", "-----------------------------------")
      msglog("OK", "Source      MAC: {0}".format(src_mac_eth))
      msglog("OK", "Destination MAC: {0}".format(dst_mac_eth))
      msglog("OK", "-----------------------------------")

    # Let's handle packets here
    if packet.type == packet.IP_TYPE:
      msglog("OK", "Found ICMP/IP packet({0}):".format(packet.IP_TYPE))
      icmpPktShim(packet)
    elif packet.type == packet.INVALID_TYPE:
      msglog("NOTE", "Found invalid packet({0})".format(packet.INVALID_TYPE))
      drop()

    # If ARP packet, then check if the packet is spoofed. 
    # If its not, then continue with the flow.
    # Yating - as for ARP packet, please refer to pox/lib/packet/arp.py
    #
    if packet.type == packet.ARP_TYPE:
      arpPktShim(packet)
    #   elif packet.payload.opcode == pkt.arp.REPLY:
    #     # Check consistency of IP address
    #     msglog("OK", "ARP packet opereation: REPLY")
    #     msglog("--->", "Checking consistency of IP address")
    #     #gTargetHardwareAddress=pkt.arp.hwdst
    #     #gDestinationAddress=



    self.macToPort[packet.src] = event.port # 1

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          if packet.type == packet.ARP_TYPE:
            if packet.payload.opcode == pkt.arp.REPLY:
              # already shim before-hand, skip
              pass
          else:
            msglog("NOTE", "Drop same port for packet {0} -> {1} on {2}@{3}".format(packet.src, packet.dst, dpid_to_str(event.dpid), port))
            drop(10)
            return
        # 6
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        msglog("OK", "Install flow: {0}@{1} -> {2}@{3}".format(packet.src, event.port, packet.dst, port))
        self.connection.send(msg)


class l2_learning (object):
  """
  All L2 switches (i.e., bridges) 'learn' the MAC addresses of the nodes 
  on the network by listening to the source addresses of packets that it sees. 
  """
  #
  # Waits for OpenFlow switches to connect and makes them smart switches
  #
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection, self.transparent)


def launch (transparent=False, hold_down=gFloodDelay):
  #
  # Now let's get started
  #
  try:
    global gFloodDelay
    # class int(x)->int or int(x, base=10)
    gFloodDelay = int(str(hold_down))
    assert gFloodDelay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(l2_learning, str_to_bool(transparent))
