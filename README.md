# GraFScaN
Tool to discover and report the configuration and security in graph databases. We analyze Neo4j and OrientDB

Requirements:

pip install -r requirements.txt

	
	------------------------
	|       GraFScaN       |
	------------------------

     An analysis graph database tool
    
	usage: GraFScaN.py [-h] [-neo4j] [-orient] [-ip IP] [-n NET] [-i FILEINPUT]
			   [-o OUTPUT] [-B] [-dict DICT] [-proxies PROXIES] [-nl]
			   [-tor] [-DoS]

	GraFScaN analyses the input to search Neo4j and OrientDB graph database.

	optional arguments:
	  -h, --help            show this help message and exit
	  -neo4j                Discover and analyze Neo4j Graph database
	  -orient               Discover and analyze Orient Graph Database
	  -ip IP                Input one ip to analyse.
	  -n NET, --network NET
				Input one network to analyse.
	  -i FILEINPUT          Input one file with one ip each line to analyse.
	  -o OUTPUT             Output file
	  -B, --bruteforce      Option to use brute force with authentication Neo4j.
	  -dict DICT            Dictionary file, one password per line
	  -proxies PROXIES      Proxies file, format: <ip>:<port>
	  -nl, --no-limit       Option to dump all database of Neo4j without auth.
	  -tor                  Option to use proxy TOR to scan de input data, need
				install and run before executed.
	  -DoS                  Option to use DoS without authentication Neo4j.

