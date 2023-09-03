# Copyright 2012 James McCauley
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

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

import joblib
import pickle, os, sys

log = core.getLogger()


class CS6501SDN_MLFW(object):
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}

    # Load ML model
    self.model = joblib.load("~/Work/pox/pox/cs6501sdn/mlfw_model.model")


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def make_flowmod_with_match(self, packet, event, hard_timeout):

    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    msg.hard_timeout = hard_timeout
    msg.buffer_id = event.ofp.buffer_id
    msg.data = event.ofp 

    return msg


  def ml_fw(self, packet, packet_in, event):
    """
    Machine-learning model-based firewall.  
    """
      
    # Variable to determine if this packet is an attack or not.
    # Default = 0 (not an attack)
    attack_predict = 0 

    # Default None values
    source_ip = None
    destination_ip = None

    if isinstance(packet.next, ipv4):

        
      ##### YOUR CODE HERE 1 - START #####
 
      # Extract packet's source IP Address

      # Extract  packet's dst IP Address

      # Hint: Some ideas are in ./pox/forwarding/l3_learning.py 

      ##### YOUR CODE HERE 1 - END   #####


    if source_ip is None or destination_ip is None:
        return

    else:
      # Check with ML model
      data = pd.DataFrame([[source_ip.toStr()[-1:],destination_ip.toStr()[-1:]]],columns=['src','dst'])

      # Predict
      attack_predict = self.model.predict(data)

      # ML model thinks we should block this packet.
      if attack_predict == 1:
        log.debug("Installing block flow entry...")

        ##### YOUR CODE HERE 2 - START #####
   
        # Create a command msg for the switch. 
        # The msg should be about installing a flow entry in the switch
        # so that the (1) the packet does not get to the intended destination and 
        # (2) the switch does not ask the controller again for another
        # 30 seconds (hard_timeout). Fulfill (1) and (2) together.
  
        # There can be multiple ways. 

        # Hint for one way.
        #  - Search for black hole (networking). Wikipedia has a good explanation.

        # Hint for another way
        #  - What does it mean you say the switch matches on a packet but takes *no* action on the packet?
  
        ##### YOUR CODE HERE 2 - END   #####

  
      # ML model thinks this is fine to forward.
      else: 

        # Learn the port for the source MAC
        self.mac_to_port[packet.src] = event.port

        # If this packet's ethernet dst address is saved before 
        # (because a host with this address once sent a packet itself before),
        # we know where which switchport to send this packet.
        if packet.dst in self.mac_to_port:

          log.debug("Installing allow flow entry...")
          msg = self.make_flowmod_with_match(packet, event, 5)

          # Add an action to this flow table entry (to forward it to a specific switchport)
          msg.actions.append(of.ofp_action_output(port = self.mac_to_port[packet.dst]))

          # Send off the command.
          self.connection.send(msg)

        else:
          # Flood the packet out everything but the input port
          self.resend_packet(packet_in, of.OFPP_ALL)


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Run the ML_FW routine
    self.ml_fw(packet, packet_in, event)


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    CS6501SDN_MLFW(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
