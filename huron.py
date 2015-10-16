### Virus Total API bulk tool codename: HURON ###
### Author: Omar Dominguez ###
### To run the script you need:  Python2.7, VT API key ###
### Input file: URL  ###
### Output file: JSON VT result ###

import json, urllib, urllib2, argparse, hashlib, re, sys
from pprint import pprint
import time


class vtAPI():
	def __init__(self):
		self.api = ''  ### Write here your VT api Key
		self.base = 'https://www.virustotal.com/vtapi/v2/'
		
	def urlScanning(self,urlScan,user="",passwd=""):
		param={'url':urlScan,'apikey':self.api}
		url= self.base + "url/scan"
		data=urllib.urlencode(param)
		proxyPath="https://" + user + ":" + passwd + "@proxy:port"
		proxy = urllib2.ProxyHandler({'https': proxyPath})
		auth = urllib2.HTTPBasicAuthHandler()
		opener = urllib2.build_opener(proxy,auth,urllib2.HTTPHandler)
		urllib2.install_opener(opener)
		result = urllib2.urlopen(url,data)
		jdata =  json.loads(result.read())

	
	def getReport(self,url2,user="",passwd=""):
		param = {'resource':url2,'apikey':self.api}
		url = self.base + "url/report"
		data = urllib.urlencode(param)
		proxyPath="https://" + user + ":" + passwd + "@proxy:port"
		proxy = urllib2.ProxyHandler({'https': proxyPath})
		auth = urllib2.HTTPBasicAuthHandler()
		opener = urllib2.build_opener(proxy,auth,urllib2.HTTPHandler)
		urllib2.install_opener(opener)
		result = urllib2.urlopen(url,data)
		jdata =  json.loads(result.read())
		return jdata
      
	  
def parsing(it,url):
	if it['response_code'] ==0:
		print "URL not found in VT"
		return 0
	print "Results in: %s [%s/%s]" %(url,it['positives'],it['total'])


def main():
	opt=argparse.ArgumentParser(description="Search and Download URL from VirusTotal")
	opt.add_argument("-s", "--search", action="store_true",dest="s", help="Search VirusTotal")
	opt.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Turn on verbosity of VT reports")
	opt.add_argument("-j", "--jsondump", action="store_true",help="Dumps the full VT report to file (VTDLXXX.json)")
	opt.add_argument("-r", "--report",action="store_true",dest="r", help="Get the report from VirusTotal")
	opt.add_argument("-up", "--user-proxy",action="store",dest="up", help="Use user proxy")
	opt.add_argument("-pp", "--password-proxy",action="store",dest="pp", help="Use password for proxy")
	opt.add_argument("-u", "--url",action="store",dest="url", help="URL to scan with VT")
	vt=vtAPI()
	options=opt.parse_args()
	if(options.up and options.pp and options.s):
		vt.urlScanning(options.url,options.up,options.pp)
	elif(options.url and options.s):
		vt.urlScanning(options.url,options.up,options.pp)
	elif(options.up and options.pp and options.r):
		parsing(vt.getReport(options.url,options.up,options.pp),options.url)
	elif(options.url and options.r):
		parsing(vt.getReport(options.url,options.up,options.pp),options.url)
	else:
		print "NO URL, no scan, no report"
	
if __name__ == '__main__':
    main()
