# GraFScaN - beta 0.1
Tool to discover and report the configuration and security in graph databases. Currently, Neo4j and OrientDB

## Requirements:

pip install -r requirements.txt

## GraFScaN Help:
	


	------------------------------------------
	|           GraFScaN  - beta 0.1         |
	|                                        |
	| Authors: Miguel Hernández (@MiguelHzBz)|
	|          Alfonso Muñoz (@mindcrypt)    |
	| Version: Beta 0.1                      |
	|                                        |
	| Date: March 3rd, 2017                  |
	------------------------------------------

	A pentesting tool for graph databases
     
    
	usage: GraFScan.py [-h] [-neo4j] [-orient] [-ip IP] [-n NET] [-i FILEINPUT]
			   [-o OUTPUT] [-b] [-dict DICT] [-proxies PROXIES] [-nl]
			   [-tor] [-DoS]

	GraFScaN analyses Neo4j and OrientDB graph databases from Internet.

	optional arguments:
	  -h, --help            show this help message and exit
	  -neo4j                Discover and analyse Neo4j Graph database
	  -orient               Discover and analyse Orient Graph Database
	  -ip IP                IP target to analyse.
	  -n NET, --network NET
				Network target to analyse.
	  -i FILEINPUT          List of targets (IPs). One IP per line.
	  -o OUTPUT             Output file
	  -b, --bruteforce      Brute-force login attack.
	  -dict DICT            Dictionary file, one password per line.
	  -proxies PROXIES      Proxies file, format: <ip>:<port>.
	  -nl, --no-limit       Option to dump all database of Neo4j without auth.
	  -tor                  Connect to the graph database target through Tor
				(previously executed).
	  -DoS                  DoS attacks. Currently, Neo4j without authentication.



## Output: 

### Neo4j with auth:

* ip: Ip analyzed.
* authentication: True.
* version: < 3.X or > 3.X.
* change_password: boolean if the bruteforce was succesfull or not, and add old_password if was true. Only if you use brute force option.

### Neo4j without auth:

* Info: Json with the return of query in cypher Match (n)-[r]-(m) Return n,r,m.
* license: Two values, version and license, communtiy or enterprise.
* NumNodes: Number of index to the nodes.
* ip: Ip analyzed.
* NumProperties: Number of index to the properties.
* NumRelationships: Number of index to the edges.
* labels: Array with all labels of nodes in the graph database.
* props: Array with all the key of all properties in the graph database.
* types: Array with all labels of edges in the graph database.
* cluster: Boolean to know if this instance is part of cluster, if the value is true, appear if this instance was slave or master.
* version: Version of Neo4j instance.

### OrientDB:

* databases: Array with all names of databases in OrientDB Server.
* version_OrientDB: Version of OrientDB Server.
* server_pass: Password of root user.
* serer_info: Json object with all info of server: connections, globalproperties, storadges and properties. Only if you use brute force option.

The tool tries to export all databases in the OrientDB Server, it creates a folder with the IP as name and puts into the compress databases. The tool only uses default auth to send the request.

## Some notes:

* If you use TOR to anonymise your IP, it is necessary to start the node instance before executed.

* If you dont put any file in output, the report is written in report.json

* If you dont put any file after the -dict option, the tool try to open dict file in the actual path.

* If you dont put any file after the -proxies option, the tool try to open proxies file in the actual path.

