//listen on tcp port 22 via ssl
//use self-signed cert
//setup logging !!(do this later just get something to work)!!
//create pid file (perhaps not quite sure how node handles this)
//startup
//import modules
//use sqlite3 npm install sqlite3
var https = require('https'),
crypto = require('crypto'),
fs = require('fs'),
sys = require('sys'),
sqlite3 = require('sqlite3');

var options = {
		key: fs.readFileSync('test-certs/server-key.pem'),
		cert: fs.readFileSync('test-certs/server-cert.pem')
};

//dirty global options
var https_port = 443; //default port
var http_port = 80; //used for proxy requests only and only port 4242
var notary_ssl_port = 4242; //used for proxied requests from other notaries

var dbname = 'convergence.db';

var test_remote_cert = function(host,port,db,clientConnection) {
	if (port == null) {
		//defaut to port 443
		port = 443;
		console.log('Port not specified, defaulting to 443');
	};

	if (host == null) {
		console.log('Hostname not specified');
		return 1; //error
	};

	var options = {
			host: host,
			port: port,
			path: '/',
			method: 'GET'
	};


	var req = https.request(options, function(res) {
		this.finalReturnJSON; 
		var location = options.host + ':' + options.port;
		console.log(location);
		var connCert = req.connection.getPeerCertificate();
		var currentTime = Math.round(new Date().getTime()/1000);

		//Determine if record for the host exists
		//if not create new record with start and finish time as the same
		//if it exists update finish time

		//check for host record

		//hash sha1 + sign with notary key

		var fingerprint = connCert.fingerprint;
		console.log(fingerprint);

		var shasum = crypto.createHash('sha1');
		shasum.update(fingerprint);
		var digest = shasum.digest('hex');
		console.log(digest);

		var signer = crypto.createSign('RSA-SHA256');
		signer.update(digest);

		var serverKey = fs.readFileSync('test-certs/server-key.pem');
		console.log('Signature: ');
		var signature = signer.sign(serverKey, output_format='hex');
		console.log(signature);
		//list of fingerprints
		returnJSON = new Object({fingerprintList:new Array(),signature:signature});

		db.get("SELECT * FROM fingerprints WHERE location = ? AND fingerprint = ? ORDER BY timestamp_finish DESC LIMIT 1", [location,fingerprint],	
				function(error, rows){
			if (rows != undefined) {
				//record exists
				db.run('UPDATE fingerprints SET timestamp_finish = ? WHERE id = ?',[currentTime,rows.id], function(error,rows){
					if (error) {
						throw error;
					} else {
						console.log('Record updated');
					};
				});
			} else {
				//record does not exit
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


		//get all matching locations and add it to the return list
		db.all('SELECT * FROM fingerprints WHERE location = ?',location,function(error,rows){
			if (error) {
				throw error;
			} else {
				for (id in rows) {
					returnJSON.fingerprintList.push({
						timestamp:{
							start: rows[id].timestamp_start,
							finish: rows[id].timestamp_finish 
						},
						fingerprint:rows[id].fingerprint
					});
				};
				clientConnection.writeHead(200);
				clientConnection.end(JSON.stringify(returnJSON));
			};
		});
		
		this.finalReturnJSON = returnJSON;

		//return JSON object (assuming everything is great)
		res.on('data', function(data) {
			//process.stdout.write(data);
		});

	});

	req.on('error', function(e) {
		//handle error send 503
		console.error(e);
		console.error('Cant connect to host');
		clientConnection.writeHead(503);
		clientConnection.end('Unable to connect to host');
	});
	
	req.end();
};

var main = function(localDB) {

	var db = localDB;

	var notaryServer = https.createServer(options);

	var notaryHandler = function (req,res) {
		if (req.method === "GET") {
			//check fingerprint vs tested fingerprint POST only
			//if match then 200
			//if invalid then 409
			//if indifferent 303
			//if there was a network error 503
			//200 and 409 respond with JSON
			/*
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
			//get the cert
			//return the fingerprint in JSON
			//cache the fingerprint in a db
			//always connects to remote host on GET
			test_remote_cert('penis.fuxpenis.com',443,db,res);
			//res.writeHead(200);
			//res.end(returnedJSON);
		} else if (req.method === "POST") {
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