### Virus Total API bulk hashes tool codename: Cacatua ###
### Author: Omar Dominguez ###
### To run the script you need:  Python2.7, VT API key ###
### Input: hash  ###
### Output file: JSON VT result ###

import json, urllib, urllib2, argparse, hashlib, re, sys
from pprint import pprint
import time

isFile=False

class vtAPI():
	def __init__(self):
		self.api = ''  ### Write here your VT api Key
		self.base = 'https://www.virustotal.com/vtapi/v2/'
	
	def getReport(self,md5,user="",passwd=""):
		param = {'resource':md5,'apikey':self.api}
		url = self.base + "file/report"
		data = urllib.urlencode(param)
		proxyPath="https://" + user + ":" + passwd + "@proxy:port"
		proxy = urllib2.ProxyHandler({'https': proxyPath})
		opener = urllib2.build_opener(proxy)
		urllib2.install_opener(opener)
		result = urllib2.urlopen(url,data)
		jdata =  json.loads(result.read())
		return jdata
		
	def rescan(self,md5,user="",passwd=""):
		param = {'resource':md5,'apikey':self.api}
		url = self.base + "file/rescan"
		data = urllib.urlencode(param)
		proxyPath="https://" + user + ":" + passwd + "@proxy:port"
		proxy = urllib2.ProxyHandler({'https': proxyPath})
		opener = urllib2.build_opener(proxy)
		urllib2.install_opener(opener)
		result = urllib2.urlopen(url,data)
		print "\n\tVirus Total Rescan Initiated for -- " + md5 + " (Requery in 10 Mins)"

def checkHASH(checkval):
	if re.match(r"([a-fA-F\d]{32})", checkval) != None:  ## Different than none is  NOT MATCHED  :: MD5
		return checkval.upper()
	elif re.match(r"([a-fA-F\d]{40})", checkval) != None:  ## Different than none is  NOT MATCHED  :: SHA1
		return checkval.upper()
	elif re.match(r"([a-fA-F\d]{64})", checkval) != None:  ## Different than none is  NOT MATCHED  :: SHA256
		return checkval.upper()
	elif re.match(r"([a-fA-F\d]{128})", checkval) != None:  ## Different than none is  NOT MATCHED  :: SHA512
		return checkval.upper()
	else:
		file=True
		md5 = md5sum(checkval)
		return md5.upper()

def checkMD5(checkval):
	if re.match(r"([a-fA-F\d]{32})", checkval) == None:
		md5 = md5sum(checkval)
		return md5.upper()
	else: 
		return checkval.upper()

def md5sum(filename):
	fh = open(filename, 'rb')
	m = hashlib.md5()
	while True:
		data = fh.read(8192)
		if not data:
			break
		m.update(data)
	return m.hexdigest() 
          
def parse(it, md5, verbose, jsondump):
	if it['response_code'] == 0:
		print md5 + " -- Not Found in VT"
		return 0
	print "\n\tResults for MD5: ",it['md5'],"\n\n\tDetected by: ",it['positives'],'/',it['total'],'\n'
	try: 
		if 'Sophos' in it['scans']:
			print '\tSophos Detection:',it['scans']['Sophos']['result'],'\n'
		if 'Kaspersky' in it['scans']:
			print '\tKaspersky Detection:',it['scans']['Kaspersky']['result'], '\n'
		if 'ESET-NOD32' in it['scans']:
			print '\tESET Detection:',it['scans']['ESET-NOD32']['result'],'\n'
		if 'McAfee' in it['scans']:
			print '\tMcAfee Detection:',it['scans']['McAfee']['result'],'\n'
		if 'McAfee-GW-Edition' in it['scans']:
			print '\tMcAfee-GW-Edition:',it['scans']['McAfee-GW-Edition']['result'],'\n'
		if 'Malwarebytes' in it['scans']:
			print '\tMalwarebytes:',it['scans']['Malwarebytes']['result'],'\n'
		print '\tScanned on:',it['scan_date']
	except:
		print " Some key failure"
	if jsondump == True:
		jsondumpfile = open("VTDL" + md5 + ".json", "w")
		pprint(it, jsondumpfile)
		jsondumpfile.close()
		print "\n\tJSON Written to File -- " + "VTDL" + md5 + ".json"
	
	if verbose == True:
		print '\n\tVerbose VirusTotal Information Output:\n'
		for x in it['scans']:
			print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',it['scans'][x]['detected'], '\t',it['scans'][x]['result']

def main():
	opt=argparse.ArgumentParser(description="Search and Download from VirusTotal")
	opt.add_argument("-s", "--search", action="store_true", help="Search VirusTotal")
	opt.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Turn on verbosity of VT reports")
	opt.add_argument("-j", "--jsondump", action="store_true",help="Dumps the full VT report to file (VTDLXXX.json)")
	opt.add_argument("-r", "--rescan",action="store_true", help="Force Rescan with Current A/V Definitions")
	opt.add_argument("-up", "--user-proxy",action="store",dest="up", help="Use user proxy")
	opt.add_argument("-pp", "--password-proxy",action="store",dest="pp", help="Use password for proxy")
	opt.add_argument("-m", "--md5",action="store",dest="md5", help="MD5 to search in VT")
	options=opt.parse_args()
	if len(sys.argv)<2:
		opt.print_help()
		sys.exit(1)
	vt=vtAPI()
	hash=options.md5
	md5 = checkMD5(hash)
	if (options.up and options.pp and not isFile):
		parse(vt.getReport(md5,options.up,options.pp), md5 ,options.verbose, options.jsondump)
	elif (options.up and options.pp and isFile):
		vt.rescan(md5)
	
if __name__ == '__main__':
    main()
