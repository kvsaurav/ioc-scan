#!/usr/bin/env python
# coding: utf-8



#Threat IOC GRAPH CO-RELATION 

# in-python-58k02xsiq
#THIS PROGRAM WILL TAKE HASH AS AN INPUT AND TRY TO FETCH EVERY SINGLE POTHENTIALY USEFUL DATA 


import hashlib
import urllib
import urllib2
import json
import os
import requests
import re
import threatcrowd
import pprint
from connector import * 

from virus_total_apis import PublicApi as VirusTotalPublicApi

API_KEY_VT = 'ADD YOUR OWN GODAMM KEY'





print ''''
	
  

	
     -------	     *  *	     ******     *
    	|  	    *    *          *           *
	|          *      *         *           *
	|          *      *         *           *
    	|           *    *          *           *
     -------         *  *            ******     *
		
===========================================================

			WElcome to IOC-REL
===========================================================

A thret RElationship Finder Between hash ,Email, ip and domain 



1 = ip 		2 = email  	3 = hash   4 = Domain  	5 = AV_name



'''''

# x = raw_input ("enter your choice ")
x = int(input("Enter a number: "))


if x==1:
	# try ip 

	# def (ip):

	ip = raw_input("Enter Ip adress :")

	print " OTX_REPORT " * 80
	pprint.pprint(threatcrowd.ip_report(ip))

	print "**" * 80
	print "VIRUSTOTAL_REPORT " * 80

	vt = VirusTotalPublicApi(API_KEY_VT)
	response = vt.get_ip_report(ip)

	print(json.dumps(response, sort_keys=False, indent=4))

	#hybrid analysis module 


elif x==2:
	# email_report(address)
	email = raw_input("Enter Email :")
	pprint.pprint(threatcrowd.email_report(email))

	print "/n"
	print "virustotal report"
	print "**" * 80


	vt = VirusTotalPublicApi(API_KEY_VT)
	response = vt.get_file_report(hash)
	print(json.dumps(response, sort_keys=False, indent=4))


elif x==3:
	# def(hash):
	hash1 = raw_input("Enter the hash : ")
	pprint.pprint(threatcrowd.file_report(hash1))
	print "/n"
	print "virustotal report"
	print "**" * 80


	vt = VirusTotalPublicApi(API_KEY_VT)
	response = vt.get_file_report(hash1)
	print(json.dumps(response, sort_keys=False, indent=4))

	print "/n","/n"

	# vt = VirusTotalPublicApi(API_KEY_VT)
	# # response = vt.get_network_traffic(hash)
	# print(json.dumps(response, sort_keys=False, indent=4))

	print ()
	print "*****" * 100
	print "/n","/n"
	print " HYBRID_ANALYSIS " * 90
	hybrid= HybridAnalysisConnector().action_search_hash(hash1)
	pprint.pprint( hybrid)


elif x==4:
	# def(domain):
	url =raw_input("Enter the domain : ")
	pprint.pprint(threatcrowd.domain_report(url))


	print "**" * 80
	print "VIRUSTOTAL_REPORT " * 80

	vt = VirusTotalPublicApi(API_KEY_VT)
	response = vt.get_domain_report(url)
	print(json.dumps(response, sort_keys=False, indent=4))


	print " HYBRID_ANALYSIS " * 90
	hybrid= HybridAnalysisConnector().action_quick_scan_url(url)
	pprint.pprint( hybrid)



elif x==5:
	# def (virus_name):
	av = raw_input("Enter the Virus Name : ")
	pprint.pprint(threatcrowd.antivirus_report(av))


else:
    print("Invalid input Please give a valid Input")



# Hybrid analysis public api 
# fetching same details for virus 
