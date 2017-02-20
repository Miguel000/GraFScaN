# GraFScaN
Tool to discover and report the configuration and security in graph databases. We analyze Neo4j and OrientDB

requirements:

pip install -r requirements.txt

	------------------------
	|       GraFScaN       |
	------------------------

     A analysis graph database tool
    
	usage: GraFScaN.py [-h] [-o OUTPUT] [-B] [-dict DICT] [-ip IP] [-n NET]
                   [-i FILEINPUT] [-nl] [-tor] [-neo4j] [-orient]

	SecGD analyse the input to search Neo4j graph database.

	optional arguments:
	  -h, --help            show this help message and exit
	  -o OUTPUT             Output file
	  -B, --bruteforce      Option to use brute force with authentication Neo4j.
	  -dict DICT            Dictionary file, one password per line
	  -ip IP                Input one ip to analyse.
	  -n NET, --network NET
				Input one network to analyse.
	  -i FILEINPUT          Input one file with one ip each line to analyse.
	  -nl, --no-limit       Option to dump all database of Neo4j without auth.
	  -tor                  Option to use proxy TOR to scan de input data, need
				install and run before executed.
	  -neo4j                Discover and analyze Neo4j Graph database
	  -orient               Discover and analyze Orient Graph Database

