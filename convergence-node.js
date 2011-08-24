//listen on tcp port 22 via ssl
//use self-signed cert
//setup logging !!(do this later just get something to work)!!
//create pid file (perhaps not quite sure how node handles this)
//startup
//import modules
//use sqlite3 npm install sqlite3
var https = require('https'),
crypto = require('crypto'),
url = require('url'),
fs = require('fs'),
sys = require('sys'),
sqlite3 = require('sqlite3'); //install via npm -- npm install sqlite3

var serverOptions = {
		key: fs.readFileSync('test-certs/server-key.pem'),
		cert: fs.readFileSync('test-certs/server-cert.pem')
};

//dirty global options
var http_port = 80; //used for proxy requests only and only port 4242
var https_port = 443; //default port
var notary_ssl_port = 4242; //used for proxied requests from other notaries

var dbname = 'convergence.db';

//function to test the remote host.
//need to pass host,port,db handle, and handle for client connection
var test_remote_cert = function(host,port,db,clientConnection,fingerprint) {
	//if no port was sent then default to 443
	if (port == null) {
		//defaut to port 443
		port = 443;
		console.log('Port not specified, defaulting to 443');
	};

	//require a hostname and error out if there is a problem
	if (host == null) {
		console.log('Hostname not specified');
		return 1; //error
	};
	
	if (fingerprint != null) {
		//handeling a post request
	};

	//options for connecting to the site
	var options = {
			host: host,
			port: port,
			path: '/',
			method: 'GET'
	};
	
	//should only connect to host IF cache mismatch and get
	//initalize the reqest
	var reqForCert = https.request(options, function(res) {
		//create the location
		var location = options.host + ':' + options.port;
		//grab the cert
		var connCert = reqForCert.connection.getPeerCertificate();
		//grab the current time # may want to push this down lower if timing is an issue
		var currentTime = Math.round(new Date().getTime()/1000);

		//Determine if record for the host exists
		//if not create new record with start and finish time as the same
		//if it exists update finish time

		//check for host record

		//pull out the fingerprint
		var fingerprint = connCert.fingerprint;
		
		//test fingerprint
		var cleanFingerprint = fingerprint.replace(/:/g, '');
		
		if (cleanFingerprint.length == 40) {
			//string ok
		} else {
			//fingerprint invalid
			clientConnection.writeHead(409);
			clientConnection.end('Fingerprint invalid');
		};

		//has the fingerprint
		var shasum = crypto.createHash('sha1');
		shasum.update(fingerprint);
		var digest = shasum.digest('hex');
		console.log(digest);

		//sign the hash with notary key
		var signer = crypto.createSign('RSA-SHA256');
		signer.update(digest);

		var serverKey = fs.readFileSync('test-certs/server-key.pem');
		console.log('Signature: ');
		var signature = signer.sign(serverKey, output_format='hex');
		console.log(signature);

		//create the json to return fingerprints
		returnJSON = new Object({fingerprintList:new Array(),signature:signature});
		
		//serialize to ensure we can get and test the data
		db.serialize(function() {
			//see if record exist, if so update the record with a new timestamp, if not then insert the record into the db
			db.get("SELECT * FROM fingerprints WHERE location = ? AND fingerprint = ? ORDER BY timestamp_finish DESC LIMIT 1", [location,fingerprint],function(error, rows){
				if (error) {
					throw error;
				} else if (rows != undefined) {
					//record exists, update record
					db.run('UPDATE fingerprints SET timestamp_finish = ? WHERE id = ?',[currentTime,rows.id], function(error,rows){
						if (error) {
							throw error;
						} else {
							console.log('Record updated');
						};
					});
				} else {
					//record does not exit so insert it into the db
					db.run('INSERT INTO fingerprints (location, fingerprint, timestamp_start, timestamp_finish) VALUES (?,?,?,?)', [location ,fingerprint,currentTime,currentTime], 
							function(error,rows){
						if (error) {
							throw error;
						} else {
							console.log('Record added');
						}
					});
				};
			});
			
			//get all matching locations and insert it into the return list
			db.all('SELECT * FROM fingerprints WHERE location = ?',location,function(error,rows){
				if (error) {
					throw error;
				} else {
					console.log(rows);
					for (id in rows) {
						returnJSON.fingerprintList.push({
							timestamp:{
								start: rows[id].timestamp_start,
								finish: rows[id].timestamp_finish 
							},
							fingerprint:rows[id].fingerprint
						});
					};
					//returning the fingerprints effectively ending the 
					clientConnection.writeHead(200);
					clientConnection.end(JSON.stringify(returnJSON));
				};
			});
		});

		//return JSON object (assuming everything is great)
		res.on('data', function(data) {
			//process.stdout.write(data);
		});

	});

	reqForCert.on('error', function(e) {
		//handle error send 503
		console.error(e);
		console.error('Cant connect to host');
		//cant connect to host, killing client's connection to the notary
		clientConnection.writeHead(503);
		clientConnection.end('Unable to connect to host');
	});
	
	//end the client request
	reqForCert.end();
};

var main = function(localDB) {
	
	//create local db handler
	var db = localDB;
	
	//initialize server
	var notaryServer = https.createServer(serverOptions);

	var notaryHandler = function (req,res) {
		if (req.method === "GET") {
			//test remote cert
			var reqDetails = url.parse(req.url);
			var splitReqDetails = reqDetails.pathname.toString().split('/',3);
			if (splitReqDetails[1] == 'target') {
				var hostAndPort = splitReqDetails[2].toString().split('+');
				var host = hostAndPort[0];
				var port = hostAndPort[1];
				if (host != null && port != null) {
					//assiming request is ok
					test_remote_cert(host,port,db,res);
				}
			}
		} else if (req.method === "POST") {
			//check fingerprint vs tested fingerprint POST only
			//recieved fingerprint
			res.writeHead(200);
			res.end('Post works');
		};
		/*
		res.writeHead(403,{
			"Access Denied":"",
			"Connection": "close"
		});
		res.end('<html>The request you issued is not an authorized Convergence Notary request.\n');
		 */
	};

	notaryServer.on('request', notaryHandler);
	notaryServer.on('upgrade', notaryHandler);

	notaryServer.on('connection',function(stream){
		console.log('connected');
	});

	notaryServer.listen(https_port);
};

//used to create and setup the database
var initDB = function(name){

	var db = new sqlite3.Database(name);

	db.run("CREATE TABLE IF NOT EXISTS fingerprints (id integer primary key, location TEXT, fingerprint TEXT, timestamp_start INTEGER, timestamp_finish INTEGER)",function(error,rows){
		if (error) {
			throw error;
		} else {
			console.log('Database initialized...');
		};
	});
	return db;
};

main(initDB(dbname));

//if match then 200
//if invalid then 409
//if indifferent 303
//if there was a network error 503
//200 and 409 respond with JSON
//get the cert
//return the fingerprint in JSON
//cache the fingerprint in a db
//always connects to remote host on GET
/* Response JSON
 * {
	"fingerprintList":
	    [
	     {
	      "timestamp":
	      {
	       "start": "<secondsSinceEpoch>",
	       "finish": "<secondsSinceEpoch>"
	      },
	      "fingerprint": "<hexEncodedFingerprint>"
	     },
	     ...
	    ],
	"signature": "<RSA_Signature>"
	}
 */

//convienence functions
if(typeof(String.prototype.trim) === "undefined") {
    String.prototype.trim = function(match,replace) {
        return String(this).replace(/^\s+|\s+$/g, '');
    };
};