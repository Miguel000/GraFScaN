# GraFScaN
Tool to discover and report the configuration and security in graph databases. Currently, Neo4j, OrientDB, ArangoDB, AllegroGraph and VirtuosoDB

## Requirements:

sudo apt-get install python-socksipy
pip install -r requirements.txt

## GraFScaN Help:
	
	------------------------------------------
-	|           GraFScaN  -  v1.0            |
-	|                                        |
-	| Authors: Miguel Hernández (@MiguelHzBz)|
-	|          Alfonso Muñoz (@mindcrypt)    |
-	| Version: Beta 0.1                      |
-	|                                        |	
-	| Last update: April 28, 2017            |	
-	------------------------------------------	
-		
-	A pentesting tool for graph databases
    
	usage: GraFScan.py [-h] [-neo4j] [-orient] [-arango] [-virtuoso] [-allegro]
                   [-all] [-ip IP] [-n NET] [-i FILEINPUT] [-o OUTPUT] [-B]
                   [-dict DICT] [-proxies PROXIES] [-nl] [-tor] [-DoS]

	GraFScaN analyses the input to search Neo4j, OrientDB, ArangoDB, AllegroGraph and VirtuosoDB graph database.

	optional arguments:
	  -h, --help            show this help message and exit
	  -neo4j                Discover and analyze Neo4j Graph database
         -orient               Discover and analyze Orient Graph Database
         -arango               Discover and analyze Arango Graph Database
         -virtuoso             Discover and analyze virtuoso Graph Database
         -allegro              Discover and analyze allegro Graph Database
         -all                  Discover and analyze All Graph Database
	  -ip IP                Input one ip to analyse.
	  -n NET, --network NET Input one network to analyse.
	  -i FILEINPUT          Input one file with one ip each line to analyse.
	  -o OUTPUT             Output file
	  -B, --bruteforce      Option to use brute force with authentication Neo4j.
	  -dict DICT            Dictionary file, one password per line
	  -proxies PROXIES      Proxies file, format: <ip>:<port>
	  -nl, --no-limit       Option to dump all database of Neo4j without auth.
	  -tor                  Option to use proxy TOR to scan de input data, need
				install and run before executed.
	  -DoS                  Option to use DoS without authentication Neo4j.


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

The tool try to export all databases in the OrientDB Server, it creates a folder with the ip as name and put into the compress databases. Only use default auth to send the request.

### ArangoDB

* Arango: True if appear in the headers response.
* IP
* Port
* Auth: False if the auth is disabled.
* Collections: List of collections in database.
* User: User with we access to the database.
* Databases: Name of databases where we can access.

### VirtuosoDB

* Virtuoso
* IP
* Port

### AllegroGraph

* AllegroGraph: True if appear in the headers response.
* IP
* Port
* Repositories: List of repositories.
* Catalogs
* User: A user other than anonymous is required
* Roles: A user other than anonymous is required.
* Anon_user: True when we access with an anonymous user.

## Some notes:

* If you use TOR to anonymize your ip, it is necessary to start the node instance before executed.

* If you dont put any file in output, the report is written in report.json

* If you dont put any file after the -dict option, the tool try to open dict file in the actual path.

* If you dont put any file after the -proxies option, the tool try to open proxies file in the actual path.

