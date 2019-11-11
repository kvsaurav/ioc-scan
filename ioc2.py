#!/usr/bin/env python
# coding: utf-8

# 
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
from termcolor import colored
import pprint
from connector import * 


from virus_total_apis import PublicApi as VirusTotalPublicApi

API_KEY_VT = 'd7959a3bbf007326c2c60d551af452e64d05b9d9b377241ee73ee2d0a08cf3d3'





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

	# ###################################################################################################
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
	otx = threatcrowd.file_report(hash1)
	# pprint.pprint(otx)
	otx_str = str(otx)
	

	print "\n" * 5
	print "**" * 80


	vt = VirusTotalPublicApi(API_KEY_VT)
	vt_response = vt.get_file_report(hash1)
	# print(json.dumps(response, sort_keys=False, indent=4))
	vt_strings = str(vt_response)


	hybrid= HybridAnalysisConnector().action_search_hash(hash1)
	# pprint.pprint( hybrid)
	# print hybrid 
	hybrid_str = str(hybrid)
	

	threat_intel = (otx_str + vt_strings + hybrid_str)
	# print z
	# print type(z)


	print "\n" * 5
	print colored(' THE IP WHICH ARE FOUND ARE ', 'red') * 30
	print "\n" * 5


	x = re.findall( r'[0-9]+(?:\.[0-9]+){3}', threat_intel )
	print x

	if (x):
	  print("YES! We have a match!")
	else:
	  print("No match")

	def repeat(s):
		threat_intel=[]
		for i in range(len(s)):
			threat_intel.append(s[:i])
		#see what it holds to give you a better picture
		print threat_intel

		# #stop at 1st element to avoid checking for the ' ' char
		# for i in threat_intel[:1:-1]:
		# 	if s.count(i) > 1 :
		# 		#find where the next repetition starts
		# 		offset = s[len(i):].find(i)

		# 		return s[:len(i)+offset]
		# 		break

		# 	return s


		# print repeat(s)

		# db349b97c37d22f5ea1d1841e3c89eb4


	print(re.search("(?P<url>https?://[^\s]+)", threat_intel).group("url"))

	# urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', threat_intel)
	# # print("Original string: ",threat_intel)
	# print "\n" * 5
	# print colored(' THE URLS WHICH ARE FOUND ARE ', 'red') * 30
	# print "\n" * 5
	# print("Urls: ",urls)

	# urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', threat_intel)
	# print("Original string: ",threat_intel)
	# print("Urls: ",urls)



	# urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
	# print("Original string: ",text)
	# print("Urls: ",urls)




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

# import requests, json
# result =  requests.get("https://www.threatcrowd.org/searchApi/v2/email/report/", 
# params = {"email": "HEALTHYBLOODPRESSURE.INFO@domainsbyproxy.com"})
# print result.text

# virustotal public api 
# we are fetching details from virus total public api 
a

# Hybrid analysis public api 
# fetching same details for virus 