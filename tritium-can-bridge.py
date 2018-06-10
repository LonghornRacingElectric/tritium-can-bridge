#!/usr/bin/python3
import socket
import struct
import socketserver
import threading
import time

# Settings - useful!
CAN_INTERFACE = 'can0'
MULTICAST_GROUP = '239.255.60.60'
PORT = 4876
BUS_ID =    0x0054726974697560      #56-bit - first 8 bits must be zero
CLIENT_ID = 0x00DEADBEEFCAFE0F      #56-bit
udp_packet_format = '>QQIB8p' # bus_id,client_id,msg_id,flags,length,data
tcp_header_format = '>IIQQ' #fwd id,fwd_range,bus_id,client_id
tcp_packet_format = '>IB8p' #id,flags,len,data
can_format = "<IB3x8s" #linux socketcan format

#TCP socket server - replies to interrogations from the Tritium can server
class ReceiveThread(threading.Thread):

    def __init__(self):
        super(ReceiveThread, self).__init__()
        # Ensure this thead dies when the application exits
        self.setDaemon(True)

    def run(self):

        host = ''
        port = 4876

        # internally this sets socket.SO_REUSEADDR, preventing errors from
        # half-closed TCP sockets
        socketserver.TCPServer.allow_reuse_address = True
        server = socketserver.TCPServer((host, port), ReceiveHandler)

        print('Listening on port {}...'.format(port))

        # serve requests forever
        server.serve_forever()

# Request handler for new TCP connections. Receives a single trajectory packet,
# posts it to the parent Qt window, then dies.
class ReceiveHandler(socketserver.BaseRequestHandler):

    def handle(self):
        print('Handling TCP connection on 4876')
        # Read the length int (number of points in this trajectory)
        len = struct.unpack('!I', self.request.recv(4, socket.MSG_WAITALL))[0]

thread_friend = ReceiveThread()
thread_friend.start()


udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

heartbeat_flags = 0x80
heartbeat_data = struct.pack('>HBBBBBB', 0, 0x0f, 0xf0, 0xef, 0xbe, 0xad, 0xde)
heartbeat_msg = struct.pack(udp_packet_format, BUS_ID, CLIENT_ID, 0, heartbeat_flags, heartbeat_data)

fake_can_msg = struct.pack(udp_packet_format, BUS_ID, CLIENT_ID, 0, 0, heartbeat_data)

print('Binding to {}'.format(CAN_INTERFACE))
# Bind the socket to the beaglebone can transceiver.
sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
sock.bind((CAN_INTERFACE,))
print('Listening for CAN packets on {}...'.format(CAN_INTERFACE))

sock.settimeout(1)

while True:

    try:
        pkt, address = sock.recvfrom(16)

        id_field, length, data = struct.unpack(can_format, pkt)
        data = data[:length] # trim data array down to size
        msg_id = id_field & socket.CAN_EFF_MASK #id_field also contains some flag bits, strip them off

        # Check: Extended CAN bus ID ???
        error_flag =        (id_field >> 29) & 1
        rtr_flag =          (id_field >> 30) & 1
        extended_flag =     (id_field >> 31) & 1

        # pack flags into tritium packet flags format
        flags = extended_flag | (rtr_flag << 1)

        print('CAN: id: {}'.format(msg_id))

        msg_out = struct.pack(udp_packet_format, BUS_ID, CLIENT_ID, msg_id, flags, data) 

        udp_sock.sendto(msg_out, (MULTICAST_GROUP, PORT))

    except socket.timeout as ex:
        print('heartbeat')
        udp_sock.sendto(heartbeat_msg, (MULTICAST_GROUP, PORT))

# socketserver?? socketserver!

